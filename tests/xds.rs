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

#[allow(warnings)]
quilkin::include_proto!("xds.core.v3");
#[allow(warnings)]
quilkin::include_proto!("google.rpc");

#[allow(warnings)]
mod envoy {
    pub mod r#type {
        pub mod matcher {
            pub mod v3 {
                #![doc(hidden)]
                tonic::include_proto!("envoy.r#type.matcher.v3");
            }
        }
        pub mod metadata {
            pub mod v3 {
                #![doc(hidden)]
                tonic::include_proto!("envoy.r#type.metadata.v3");
            }
        }
        pub mod tracing {
            pub mod v3 {
                #![doc(hidden)]
                tonic::include_proto!("envoy.r#type.tracing.v3");
            }
        }
        pub mod v3 {
            #![doc(hidden)]
            tonic::include_proto!("envoy.r#type.v3");
        }
    }
    pub mod config {
        pub mod accesslog {
            pub mod v3 {
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.accesslog.v3");
            }
        }
        pub mod cluster {
            pub mod v3 {
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.cluster.v3");
            }
        }
        pub mod core {
            pub mod v3 {
                #![allow(clippy::large_enum_variant)]
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.core.v3");
            }
        }
        pub mod endpoint {
            pub mod v3 {
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.endpoint.v3");
            }
        }
        pub mod listener {
            pub mod v3 {
                #![allow(clippy::large_enum_variant)]
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.listener.v3");
            }
        }
        pub mod route {
            pub mod v3 {
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.route.v3");
            }
        }
    }
    pub mod service {
        pub mod discovery {
            pub mod v3 {
                #![allow(clippy::unit_arg)]
                #![doc(hidden)]
                tonic::include_proto!("envoy.service.discovery.v3");
            }
        }
        pub mod cluster {
            pub mod v3 {
                #![allow(clippy::unit_arg)]
                #![doc(hidden)]
                tonic::include_proto!("envoy.service.cluster.v3");
            }
        }
    }
}

#[allow(warnings)]
mod quilkin_proto {
    pub mod extensions {
        pub mod filters {
            pub mod concatenate_bytes {
                pub mod v1alpha1 {
                    #![doc(hidden)]
                    tonic::include_proto!("quilkin.extensions.filters.concatenate_bytes.v1alpha1");
                }
            }
        }
    }
}

use envoy::config::cluster::v3::{cluster::ClusterDiscoveryType, Cluster};
use envoy::config::core::v3::{address, socket_address::PortSpecifier, Address, SocketAddress};
use envoy::config::endpoint::v3::{
    lb_endpoint::HostIdentifier, ClusterLoadAssignment, Endpoint, LbEndpoint, LocalityLbEndpoints,
};
use envoy::config::listener::v3::{
    filter::ConfigType, Filter as LdsFilter, FilterChain as LdsFilterChain, Listener,
};
use envoy::service::discovery::v3::aggregated_discovery_service_server::{
    AggregatedDiscoveryService as ADS, AggregatedDiscoveryServiceServer as ADSServer,
};
use envoy::service::discovery::v3::{
    DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use quilkin_proto::extensions::filters::concatenate_bytes::v1alpha1::concatenate_bytes::{
    Strategy, StrategyValue,
};
use quilkin_proto::extensions::filters::concatenate_bytes::v1alpha1::ConcatenateBytes;

use quilkin::config::Config;
use quilkin::test_utils::{logger, TestHelper};
use quilkin::Builder;

use prost::Message;
use slog::{info, o, Logger};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
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
    log: Logger,
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

        let log = self.log.clone();
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
                                info!(log, "Stopping updates to client: source was dropped");
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
dynamic:
  management_servers:
    - address: http://127.0.0.1:23456
    ";

    let config: Arc<Config> = Arc::new(serde_yaml::from_str(config).unwrap());
    let server = Builder::from(config)
        .with_log(logger())
        .validate()
        .unwrap()
        .build();

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let (ready_tx, _ready_rx) = tokio::sync::oneshot::channel();
    let (discovery_response_tx, discovery_response_rx) = mpsc::channel(1);

    let mut control_plane_shutdown_rx = shutdown_rx.clone();
    let log = t.log.new(o!("source" => "control-plane"));
    tokio::spawn(async move {
        let server = ADSServer::new(ControlPlane {
            source_discovery_response_rx: tokio::sync::Mutex::new(Some(discovery_response_rx)),
            log,
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
        server.run(ready_tx, shutdown_rx).await.unwrap();
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

        let expected_response = format!("a{}{}", b1, b2);
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
                    if let Ok(response) = time::timeout(Duration::from_millis(500), response_rx.recv()).await {
                        let response = response.unwrap();
                        if expected_response == response {
                            break;
                        }
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
    let filter_name = "quilkin.extensions.filters.concatenate_bytes.v1alpha1.ConcatenateBytes";
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
    endpoint_addr: SocketAddr,
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
fn create_cluster_resource(name: &str, endpoint_addr: SocketAddr) -> Cluster {
    Cluster {
        name: name.into(),
        transport_socket_matches: vec![],
        alt_stat_name: "".into(),
        eds_cluster_config: None,
        connect_timeout: None,
        per_connection_buffer_limit_bytes: None,
        lb_policy: 0,
        load_balancing_policy: None,
        load_assignment: Some(create_endpoint_resource(name, endpoint_addr)),
        health_checks: vec![],
        max_requests_per_connection: None,
        circuit_breakers: None,
        upstream_http_protocol_options: None,
        common_http_protocol_options: None,
        http_protocol_options: None,
        http2_protocol_options: None,
        typed_extension_protocol_options: HashMap::new(),
        dns_refresh_rate: None,
        dns_failure_refresh_rate: None,
        respect_dns_ttl: false,
        dns_lookup_family: 0,
        dns_resolvers: vec![],
        use_tcp_for_dns_lookups: false,
        outlier_detection: None,
        cleanup_interval: None,
        upstream_bind_config: None,
        lb_subset_config: None,
        common_lb_config: None,
        transport_socket: None,
        metadata: None,
        protocol_selection: 0,
        upstream_connection_options: None,
        close_connections_on_host_health_failure: false,
        ignore_health_on_host_removal: false,
        filters: vec![],
        lrs_server: None,
        track_timeout_budgets: false,
        upstream_config: None,
        track_cluster_stats: None,
        preconnect_policy: None,
        connection_pool_per_downstream_connection: false,
        cluster_discovery_type: Some(ClusterDiscoveryType::Type(0)),
        lb_config: None,
    }
}

fn create_endpoint_resource(cluster_name: &str, address: SocketAddr) -> ClusterLoadAssignment {
    ClusterLoadAssignment {
        cluster_name: cluster_name.into(),
        endpoints: vec![LocalityLbEndpoints {
            locality: None,
            lb_endpoints: vec![LbEndpoint {
                health_status: 0,
                metadata: None,
                load_balancing_weight: None,
                host_identifier: Some(HostIdentifier::Endpoint(Endpoint {
                    address: Some(Address {
                        address: Some(address::Address::SocketAddress(SocketAddress {
                            protocol: 1,
                            address: address.ip().to_string(),
                            resolver_name: "".into(),
                            ipv4_compat: true,
                            port_specifier: Some(PortSpecifier::PortValue(address.port() as u32)),
                        })),
                    }),
                    health_check_config: None,
                    hostname: "".into(),
                })),
            }],
            load_balancing_weight: None,
            priority: 0,
            proximity: None,
        }],
        named_endpoints: HashMap::new(),
        policy: None,
    }
}

#[allow(deprecated)]
fn create_lds_filter_chain(filters: Vec<LdsFilter>) -> LdsFilterChain {
    LdsFilterChain {
        filter_chain_match: None,
        filters,
        use_proxy_proto: None,
        metadata: None,
        transport_socket: None,
        transport_socket_connect_timeout: None,
        name: "test-lds-filter-chain".into(),
        on_demand_configuration: None,
    }
}

#[allow(deprecated)]
fn create_lds_listener(name: String, filter_chains: Vec<LdsFilterChain>) -> Listener {
    Listener {
        name,
        address: None,
        filter_chains,
        default_filter_chain: None,
        use_original_dst: None,
        per_connection_buffer_limit_bytes: None,
        metadata: None,
        deprecated_v1: None,
        drain_type: 0,
        listener_filters: vec![],
        listener_filters_timeout: None,
        continue_on_listener_filters_timeout: false,
        transparent: None,
        freebind: None,
        socket_options: vec![],
        tcp_fast_open_queue_length: None,
        traffic_direction: 0,
        udp_listener_config: None,
        api_listener: None,
        connection_balance_config: None,
        reuse_port: false,
        access_log: vec![],
        udp_writer_config: None,
        tcp_backlog_size: None,
        bind_to_port: None,
        listener_specifier: None,
    }
}
