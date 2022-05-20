/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use quilkin::{
    config::Config,
    endpoint::{Endpoint, EndpointAddress},
    test_utils::TestHelper,
    xds::{
        config::{
            cluster::v3::{cluster::ClusterDiscoveryType, Cluster},
            endpoint::v3::{ClusterLoadAssignment, LocalityLbEndpoints},
            listener::v3::{
                filter::ConfigType, Filter as LdsFilter, FilterChain as LdsFilterChain, Listener,
            },
        },
        service::discovery::v3::{
            aggregated_discovery_service_server::{
                AggregatedDiscoveryService as ADS, AggregatedDiscoveryServiceServer as ADSServer,
            },
            DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
        },
    },
};

tonic::include_proto!("quilkin.filters.concatenate_bytes.v1alpha1");

use concatenate_bytes::{Strategy, StrategyValue};

use prost::Message;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::time;
use tonic::transport::Server;

const CLUSTER_TYPE: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const LISTENER_TYPE: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";

// A test xDS server implementation that waits for a client to connect and
// forwards DiscoveryResponse(s) to the client. A rx chan is passed in upon creation
// and can be used by the test to drive the DiscoveryResponses sent by the server to the client.
struct ControlPlane {
    source_discovery_response_rx:
        tokio::sync::Mutex<Option<mpsc::Receiver<Result<DiscoveryResponse, tonic::Status>>>>,
    shutdown_rx: watch::Receiver<()>,
}

#[tonic::async_trait]
impl ADS for ControlPlane {
    type StreamAggregatedResourcesStream =
        tokio_stream::wrappers::ReceiverStream<Result<DiscoveryResponse, tonic::Status>>;
    type DeltaAggregatedResourcesStream =
        tokio_stream::wrappers::ReceiverStream<Result<DeltaDiscoveryResponse, tonic::Status>>;

    async fn stream_aggregated_resources(
        &self,
        _request: tonic::Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::StreamAggregatedResourcesStream>, tonic::Status> {
        let mut source_discovery_response_rx = self
            .source_discovery_response_rx
            .lock()
            .await
            .take()
            .unwrap();

        let mut shutdown_rx = self.shutdown_rx.clone();
        let (discovery_response_tx, discovery_response_rx) = mpsc::channel(1);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        return;
                    }
                    source_response = source_discovery_response_rx.recv() => {
                        match source_response {
                            None => {
                                tracing::info!("Stopping updates to client: source was dropped");
                                return;
                            },
                            Some(result) => {
                                let _ = discovery_response_tx.send(result).await.unwrap();
                            }
                        }
                    }
                }
            }
        });
        Ok(tonic::Response::new(
            tokio_stream::wrappers::ReceiverStream::new(discovery_response_rx),
        ))
    }

    async fn delta_aggregated_resources(
        &self,
        _request: tonic::Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::DeltaAggregatedResourcesStream>, tonic::Status> {
        unimplemented!()
    }
}

#[tokio::test]
async fn send_cds_and_lds_updates() {
    let mut t = TestHelper::default();

    let config = "
version: v1alpha1
proxy:
  id: test-proxy
  port: 34567
management_servers:
  - address: http://127.0.0.1:23456
    ";

    let config: Config = serde_yaml::from_str(config).unwrap();
    let server = quilkin::Server::try_from(config).unwrap();

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let (discovery_response_tx, discovery_response_rx) = mpsc::channel(1);

    let mut control_plane_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        let server = ADSServer::new(ControlPlane {
            source_discovery_response_rx: tokio::sync::Mutex::new(Some(discovery_response_rx)),
            shutdown_rx: control_plane_shutdown_rx.clone(),
        });
        let server = Server::builder().add_service(server);
        server
            .serve_with_shutdown("0.0.0.0:23456".parse().unwrap(), async move {
                let _: Result<(), _> = control_plane_shutdown_rx.changed().await;
            })
            .await
            .unwrap();
    });

    // Run the server.
    tokio::spawn(async move {
        server.run(shutdown_rx).await.unwrap();
    });

    let timeout = time::sleep(Duration::from_secs(10));
    tokio::pin!(timeout);

    // Each time, we create a new upstream endpoint and send a cluster update for it.
    let concat_bytes = vec![("b", "c,"), ("d", "e")];
    for (i, (b1, b2)) in concat_bytes.into_iter().enumerate() {
        let upstream_address = t.run_echo_server().await;

        // Send a cluster update.
        let cluster_update = cluster_discovery_response(
            "cluster-1".into(),
            i.to_string().as_str(),
            i.to_string().as_str(),
            upstream_address,
        );
        discovery_response_tx
            .send(Ok(cluster_update))
            .await
            .unwrap();

        // Send a filter update.
        let filter_update = concat_listener_discovery_response(
            i.to_string().as_str(),
            i.to_string().as_str(),
            vec![b1.into(), b2.into()],
        );
        discovery_response_tx.send(Ok(filter_update)).await.unwrap();

        // Open a socket we can use to talk to the proxy and receive response back on.
        let (mut response_rx, socket) = t.open_socket_and_recv_multiple_packets().await;

        let expected_response = format!("a{b1}{b2}");
        let mut interval = time::interval(Duration::from_millis(10));
        loop {
            // Send a packet, it should be suffixed with the new filter configs.
            // Then wait to receive a response. Try until the update is applied
            // and we receive the expected response.
            socket
                .send_to(b"a", &"127.0.0.1:34567".parse::<SocketAddr>().unwrap())
                .await
                .unwrap();

            tokio::select! {
                _ = &mut timeout => {
                    unreachable!("timed-out waiting for xDS update to be applied")
                },
                _ = interval.tick() => {
                    // If we time out, it could mean that we haven't applied any cluster update yet so we
                    // are dropping packets. In which case we can simply retry later.
                    // If its for any other reason, our assertion will fail later or we will time out.
                    if time::timeout(Duration::from_millis(500), response_rx.changed()).await.is_ok() && expected_response == *response_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }
}

fn concat_listener_discovery_response(
    version_info: &str,
    nonce: &str,
    bytes: Vec<Vec<u8>>,
) -> DiscoveryResponse {
    let filter_name = "quilkin.filters.concatenate_bytes.v1alpha1.ConcatenateBytes";
    let filters = bytes
        .into_iter()
        .map(|value| LdsFilter {
            name: filter_name.into(),
            config_type: Some(ConfigType::TypedConfig({
                let mut buf = vec![];
                ConcatenateBytes {
                    on_write: None,
                    on_read: Some(StrategyValue {
                        value: Strategy::Append as i32,
                    }),
                    bytes: value,
                }
                .encode(&mut buf)
                .unwrap();
                prost_types::Any {
                    type_url: filter_name.into(),
                    value: buf,
                }
            })),
        })
        .collect();

    let filter_chain = create_lds_filter_chain(filters);

    let listener_name = "listener-1";
    let listener = create_lds_listener(listener_name.into(), vec![filter_chain]);
    let mut buf = vec![];
    listener.encode(&mut buf).unwrap();
    let lds_resource = prost_types::Any {
        type_url: LISTENER_TYPE.into(),
        value: buf,
    };

    DiscoveryResponse {
        version_info: version_info.into(),
        resources: vec![lds_resource],
        canary: false,
        type_url: LISTENER_TYPE.into(),
        nonce: nonce.into(),
        control_plane: None,
    }
}

fn cluster_discovery_response(
    name: String,
    version_info: &str,
    nonce: &str,
    endpoint_addr: EndpointAddress,
) -> DiscoveryResponse {
    let cluster = create_cluster_resource(&name, endpoint_addr);
    let mut value = vec![];
    cluster.encode(&mut value).unwrap();
    let resource = prost_types::Any {
        type_url: CLUSTER_TYPE.into(),
        value,
    };

    DiscoveryResponse {
        type_url: CLUSTER_TYPE.into(),
        version_info: version_info.into(),
        nonce: nonce.into(),
        resources: vec![resource],
        canary: false,
        control_plane: None,
    }
}

#[allow(deprecated)]
fn create_cluster_resource(name: &str, endpoint_addr: EndpointAddress) -> Cluster {
    Cluster {
        name: name.into(),
        load_assignment: Some(create_endpoint_resource(name, endpoint_addr)),
        cluster_discovery_type: Some(ClusterDiscoveryType::Type(0)),
        ..<_>::default()
    }
}

fn create_endpoint_resource(cluster_name: &str, address: EndpointAddress) -> ClusterLoadAssignment {
    ClusterLoadAssignment {
        cluster_name: cluster_name.into(),
        endpoints: vec![LocalityLbEndpoints {
            lb_endpoints: vec![Endpoint::new(address).into()],
            ..<_>::default()
        }],
        ..<_>::default()
    }
}

fn create_lds_filter_chain(filters: Vec<LdsFilter>) -> LdsFilterChain {
    LdsFilterChain {
        name: "test-lds-filter-chain".into(),
        filters,
        ..<_>::default()
    }
}

fn create_lds_listener(name: String, filter_chains: Vec<LdsFilterChain>) -> Listener {
    Listener {
        name,
        filter_chains,
        ..<_>::default()
    }
}
