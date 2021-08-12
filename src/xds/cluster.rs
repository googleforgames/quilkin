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

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    net::SocketAddr,
};

use bytes::Bytes;
use prost::Message;
use slog::{debug, o, warn, Logger};
use tokio::sync::mpsc;

use crate::{
    cluster::{Cluster as ProxyCluster, ClusterLocalities, Locality, LocalityEndpoints},
    endpoint::Endpoint,
    metadata::Metadata,
    xds::{
        ads_client::send_discovery_req,
        envoy::{
            config::{
                cluster::v3::{cluster, Cluster},
                core::v3::{address, socket_address},
                endpoint::v3::{lb_endpoint, ClusterLoadAssignment},
            },
            service::discovery::v3::{DiscoveryRequest, DiscoveryResponse},
        },
        error::Error,
        CLUSTER_TYPE, ENDPOINT_TYPE,
    },
};

/// Tracks clusters and endpoints reported by an XDS server.
/// This struct handles, parsing and aggregating XDS DiscoveryResponse
/// resources and exposes the results to the caller whenever
/// the result changes.
pub(crate) struct ClusterManager {
    log: Logger,

    // Send discovery requests ACKs/NACKs to the server.
    discovery_req_tx: mpsc::Sender<DiscoveryRequest>,

    // Sends cluster state updates to the caller.
    cluster_updates_tx: mpsc::Sender<HashMap<String, ProxyCluster>>,

    // Tracks each cluster's endpoints and localities.
    clusters: HashMap<String, ProxyCluster>,

    // Tracks the (version, nonce) state for EDS request/response.
    // This is used to make spontaneous EDS requests to
    // subscribe to the latest cluster set anytime the set changes.
    last_seen_cluster_load_assignment_version: Option<(String, String)>,
}

impl ClusterManager {
    /// Creates a new [`ClusterManager`].
    /// Cluster updates are sent on the provided channel. DiscoveryRequest
    /// ACKs/NACKs are sent on the provided channel to be forwarded to the XDS
    /// server.
    pub(in crate::xds) fn new(
        base: Logger,
        cluster_updates_tx: mpsc::Sender<HashMap<String, ProxyCluster>>,
        discovery_req_tx: mpsc::Sender<DiscoveryRequest>,
    ) -> Self {
        ClusterManager {
            log: base.new(o!("source" => "xds::ClusterManager")),
            discovery_req_tx,
            cluster_updates_tx,
            clusters: HashMap::new(),
            last_seen_cluster_load_assignment_version: None,
        }
    }

    /// Processes a CDS response and updates its cluster view if needed.
    /// This method is called upon receiving a `CDS` `DiscoveryResponse` from the XDS server.
    pub(in crate::xds) async fn on_cluster_response(&mut self, response: DiscoveryResponse) {
        debug!(
            self.log,
            "{}: received response containing {} resource(s)",
            CLUSTER_TYPE,
            response.resources.len()
        );

        let error_message = self
            .process_cluster_response(response.resources)
            .await
            .err()
            .map(|err| err.message);

        self.send_cluster_discovery_req(response.version_info, response.nonce, error_message)
            .await;
    }

    async fn process_cluster_response(
        &mut self,
        resources: Vec<prost_types::Any>,
    ) -> Result<(), Error> {
        let mut temp_cluster_set = HashMap::new();
        for resource in resources {
            let cluster = Cluster::decode(Bytes::from(resource.value))
                .map_err(|err| Error::new(format!("cluster decode error: {}", err.to_string())))?;

            // If this cluster doesn't use IP addresses return an error.
            cluster
                .cluster_discovery_type
                .map(|discovery_type| match discovery_type {
                    // See envoy::config::cluster::v3::cluster::DiscoveryType for corresponding values.
                    cluster::ClusterDiscoveryType::Type(discovery_type) if discovery_type == 0 => {
                        Ok(())
                    }
                    cluster::ClusterDiscoveryType::Type(discovery_type) => Err(format!(
                        "unsupported cluster type '{}': Only STATIC is supported",
                        discovery_type
                    )),
                    cluster::ClusterDiscoveryType::ClusterType(_) => {
                        Err("Custom cluster types are not supported".into())
                    }
                })
                .unwrap_or_else(|| Err("no cluster_discovery_type was provided in request".into()))
                .map_err(Error::new)?;

            let localities = cluster
                .load_assignment
                .map(ClusterManager::process_cluster_load_assignment)
                .unwrap_or_else(|| Ok(HashMap::new()))?;

            temp_cluster_set.insert(cluster.name, ProxyCluster { localities });
        }

        // Update to the new cluster set.
        std::mem::swap(&mut temp_cluster_set, &mut self.clusters);

        // Send the new cluster set downstream.
        self.send_cluster_update().await;

        // If we have any added/removed clusters, we need to update our ClusterLoadAssignment watch.
        // This also handles deletion - if a previously existing cluster wasn't returned in a response,
        // then it has been deleted on the server-side. We don't have any explicit cleanup to do since
        // we always recreate the cluster set - ClusterLoadAssignment watch
        // always subscribes only to the current cluster set so cleanup there is implicit.
        if temp_cluster_set.keys().collect::<HashSet<_>>()
            != self.clusters.keys().collect::<HashSet<_>>()
        {
            let (version_info, response_nonce) = self
                .last_seen_cluster_load_assignment_version
                .clone()
                .unwrap_or_else(|| ("".into(), "".into()));

            self.send_cluster_load_assignment_discovery_req(version_info, response_nonce, None)
                .await;
        }

        Ok(())
    }

    /// Processes an EDS response and updates its endpoint view if needed.
    /// This method is called upon receiving an `EDS` `DiscoveryResponse` from the XDS server.
    pub(in crate::xds) async fn on_cluster_load_assignment_response(
        &mut self,
        response: DiscoveryResponse,
    ) {
        debug!(
            self.log,
            "{}: received response containing {} resource(s)",
            ENDPOINT_TYPE,
            response.resources.len()
        );

        self.last_seen_cluster_load_assignment_version =
            Some((response.version_info.clone(), response.nonce.clone()));

        let error_message = self
            .process_cluster_load_assignment_response(response.resources)
            .await
            .err()
            .map(|err| err.message);

        self.send_cluster_load_assignment_discovery_req(
            response.version_info,
            response.nonce,
            error_message,
        )
        .await;
    }

    async fn process_cluster_load_assignment_response(
        &mut self,
        resources: Vec<prost_types::Any>,
    ) -> Result<(), Error> {
        for resource in resources {
            let assignment =
                ClusterLoadAssignment::decode(Bytes::from(resource.value)).map_err(|err| {
                    Error::new(format!(
                        "cluster load assignment decode error: {}",
                        err.to_string()
                    ))
                })?;

            match self.clusters.get_mut(&assignment.cluster_name) {
                Some(cluster) => {
                    // Update the cluster's localities.
                    cluster.localities =
                        ClusterManager::process_cluster_load_assignment(assignment)?;
                }
                None => {
                    // Got an endpoint that we don't have a cluster for. This likely means that
                    // the cluster has been deleted since ADS handles resource ordering.
                    warn!(
                        self.log,
                        "Got endpoint for non-existing cluster"; "name" => assignment.cluster_name
                    );
                }
            }
        }

        // Send any cluster update downstream.
        self.send_cluster_update().await;

        Ok(())
    }

    // Send the current cluster state downstream.
    async fn send_cluster_update(&mut self) {
        self.cluster_updates_tx
            .send(self.clusters.clone())
            .await
            .map_err(|err| {
                warn!(self.log, "Failed to send cluster updates downstream");
                err
            })
            // ok is safe here because an error can only be due to downstream dropping
            // the receiving side and we can't do much about that since it could mean
            // that they're no longer interested or we're shutting down.
            .ok();
    }

    /// Parses a ClusterLoadAssignment response into the endpoint
    /// components that we're interested in.
    fn process_cluster_load_assignment(
        mut assignment: ClusterLoadAssignment,
    ) -> Result<ClusterLocalities, Error> {
        let mut existing_endpoints = HashMap::new();

        for lb_locality in assignment.endpoints {
            let locality = lb_locality.locality.map(|locality| Locality {
                region: locality.region,
                zone: locality.zone,
                sub_zone: locality.sub_zone,
            });

            // Extract components of the endpoint that we care about.
            let mut endpoints = vec![];
            for (host_identifier, metadata) in
                lb_locality
                    .lb_endpoints
                    .into_iter()
                    .filter_map(|lb_endpoint| {
                        let metadata = lb_endpoint.metadata;
                        lb_endpoint
                            .host_identifier
                            .map(|host_identifier| (host_identifier, metadata))
                    })
            {
                let endpoint = match host_identifier {
                    lb_endpoint::HostIdentifier::Endpoint(endpoint) => Ok(endpoint),
                    lb_endpoint::HostIdentifier::EndpointName(name_reference) => {
                        match assignment.named_endpoints.remove(&name_reference) {
                            Some(endpoint) => Ok(endpoint),
                            None => Err(Error::new(format!(
                                "no endpoint found name reference {}",
                                name_reference
                            ))),
                        }
                    }
                }?;

                // Extract the endpoint's address.
                let address = endpoint
                    .address
                    .and_then(|address| address.address)
                    .map(|address| match address {
                        address::Address::SocketAddress(sock_addr) => {
                            // We only support IP addresses so anything else is an error.
                            let address =
                                sock_addr
                                    .address
                                    .parse::<std::net::IpAddr>()
                                    .map_err(|err| {
                                        Error::new(format!("invalid ip address: {}", err))
                                    })?;
                            sock_addr
                                .port_specifier
                                .map(|port_specifier| match port_specifier {
                                    socket_address::PortSpecifier::PortValue(port) => {
                                        Ok((address, port as u16))
                                    }
                                    socket_address::PortSpecifier::NamedPort(_) => Err(Error::new(
                                        "named_port on socket addresses is not supported",
                                    )),
                                })
                                .unwrap_or_else(|| {
                                    Err(Error::new("no port specifier was provided"))
                                })
                        }
                        invalid => Err(Error::new(format!(
                            "unsupported endpoint address type: {:?}",
                            invalid
                        ))),
                    })
                    .unwrap_or_else(|| Err(Error::new("received `Endpoint` with no `address`")))?;

                endpoints.push(Endpoint::with_metadata(
                    SocketAddr::from(address),
                    metadata
                        .map(Metadata::try_from)
                        .transpose()
                        .map_err(Error::new)?
                        .unwrap_or_default(),
                ));
            }

            existing_endpoints.insert(locality, LocalityEndpoints { endpoints });
        }

        Ok(existing_endpoints)
    }

    // Notify that we are about to reconnect the GRPC stream.
    pub(in crate::xds) fn on_reconnect(&mut self) {
        // Reset any last seen version and nonce since we'll be working
        // with a new connection from now on with a clean slate.
        self.last_seen_cluster_load_assignment_version = None
    }

    // Send a CDS ACK/NACK request to the server.
    async fn send_cluster_discovery_req(
        &mut self,
        version_info: String,
        response_nonce: String,
        error_message: Option<String>,
    ) {
        self.send_discovery_req(
            CLUSTER_TYPE,
            version_info,
            response_nonce,
            error_message,
            vec![],
        )
        .await;
    }

    // Send an EDS ACK/NACK request to the server.
    async fn send_cluster_load_assignment_discovery_req(
        &mut self,
        version_info: String,
        response_nonce: String,
        error_message: Option<String>,
    ) {
        self.send_discovery_req(
            ENDPOINT_TYPE,
            version_info,
            response_nonce,
            error_message,
            self.clusters.keys().cloned().collect(),
        )
        .await;
    }

    // Send a DiscoveryRequest ACK/NACK back to the server for the given version and nonce.
    async fn send_discovery_req(
        &mut self,
        type_url: &'static str,
        version_info: String,
        response_nonce: String,
        error_message: Option<String>,
        resource_names: Vec<String>,
    ) {
        send_discovery_req(
            self.log.clone(),
            type_url,
            version_info,
            response_nonce,
            error_message,
            resource_names,
            &mut self.discovery_req_tx,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{ClusterManager, ProxyCluster};
    use crate::endpoint::Endpoint as ProxyEndpoint;
    use crate::test_utils::logger;
    use crate::xds::envoy::config::cluster::v3::{cluster::ClusterDiscoveryType, Cluster};
    use crate::xds::envoy::config::core::v3::{
        address, socket_address::PortSpecifier, Address, Metadata, SocketAddress,
    };
    use crate::xds::envoy::config::endpoint::v3::{
        lb_endpoint::HostIdentifier, ClusterLoadAssignment, Endpoint, LbEndpoint,
        LocalityLbEndpoints,
    };
    use crate::xds::envoy::service::discovery::v3::{DiscoveryRequest, DiscoveryResponse};
    use crate::xds::{CLUSTER_TYPE, ENDPOINT_TYPE};
    use prost::Message;
    use prost_types::value::Kind;
    use prost_types::Struct as ProstStruct;
    use prost_types::Value as ProstValue;
    use std::collections::{HashMap, HashSet};
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    type ClusterState = HashMap<String, ProxyCluster>;

    #[tokio::test]
    async fn watch_endpoints_for_new_clusters() {
        // Test that whenever we receive a new cluster, we add it to
        // the endpoint watch list.

        let (cluster_updates_tx, _) = mpsc::channel::<ClusterState>(100);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cm = ClusterManager::new(logger(), cluster_updates_tx, discovery_req_tx);

        let initial_names = vec!["a".into()];
        cm.on_cluster_response(cluster_discovery_response("1", "2", initial_names.clone()))
            .await;

        // Check that we send both endpoint and cluster watch requests.
        let (cluster_req, endpoint_req) =
            recv_cluster_and_endpoint_reqs(&mut discovery_req_rx).await;
        assert_ack_req(&cluster_req);
        assert_ack_req(&endpoint_req);

        assert_req_contains_resource_names(&cluster_req, &[]);
        assert_req_contains_resource_names(&endpoint_req, &initial_names);

        assert_req_version_and_nonce(&cluster_req, "1", "2");
        assert_req_version_and_nonce(&endpoint_req, "", "");

        // Send an updated list of clusters.
        let updated_names = vec!["a".into(), "b".into()];
        cm.on_cluster_response(cluster_discovery_response("3", "6", updated_names.clone()))
            .await;

        // Check that the new cluster is included in the endpoint watch request.
        let (cluster_req, endpoint_req) =
            recv_cluster_and_endpoint_reqs(&mut discovery_req_rx).await;
        assert_ack_req(&cluster_req);
        assert_ack_req(&endpoint_req);

        assert_req_contains_resource_names(&cluster_req, &[]);
        assert_req_contains_resource_names(&endpoint_req, &updated_names);

        assert_req_version_and_nonce(&cluster_req, "3", "6");
        assert_req_version_and_nonce(&endpoint_req, "", "");
    }

    #[tokio::test]
    async fn endpoint_updates() {
        // Test that whenever we receive endpoint changes, we update our cluster state.

        let (cluster_updates_tx, _) = mpsc::channel::<ClusterState>(100);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cm = ClusterManager::new(logger(), cluster_updates_tx, discovery_req_tx);

        let names = vec!["a".into(), "b".into()];
        cm.on_cluster_response(cluster_discovery_response("3", "6", names.clone()))
            .await;

        let _ = recv_cluster_and_endpoint_reqs(&mut discovery_req_rx).await;

        let mut version = 4;
        let mut nonce = 9;
        for _ in 0..3 {
            let v = &version.to_string();
            let n = &nonce.to_string();

            let new_address = format!("127.0.0.{}", nonce);
            let new_port = 2020 + nonce;
            let expected_socket_addr = format!("{}:{}", new_address, new_port)
                .parse::<SocketAddr>()
                .unwrap();
            cm.on_cluster_load_assignment_response(endpoint_discovery_response_with_update(
                v,
                n,
                names.clone(),
                |mut assignment| {
                    if &assignment.cluster_name == "a" {
                        assignment.endpoints[0].lb_endpoints[0].host_identifier =
                            Some(HostIdentifier::Endpoint(Endpoint {
                                address: Some(Address {
                                    address: Some(address::Address::SocketAddress(SocketAddress {
                                        protocol: 1,
                                        address: new_address.clone(),
                                        resolver_name: "".into(),
                                        ipv4_compat: true,
                                        port_specifier: Some(PortSpecifier::PortValue(new_port)),
                                    })),
                                }),
                                health_check_config: None,
                                hostname: "".into(),
                            }));
                    }
                    assignment
                },
            ))
            .await;

            // Check ACK request.
            let endpoint_req = discovery_req_rx.recv().await.unwrap();
            assert_ack_req(&endpoint_req);
            assert_req_contains_resource_names(&endpoint_req, &names);
            assert_req_version_and_nonce(&endpoint_req, v, n);

            version += 1;
            nonce += 1;

            // Check that we have updated our cluster state.
            assert_eq!(
                cm.clusters
                    .get("a")
                    .unwrap()
                    .localities
                    .get(&None)
                    .unwrap()
                    .endpoints,
                vec![ProxyEndpoint::new(expected_socket_addr)]
            );
            assert_eq!(
                cm.clusters
                    .get("b")
                    .unwrap()
                    .localities
                    .get(&None)
                    .unwrap()
                    .endpoints,
                vec![ProxyEndpoint::new("127.0.0.1:2020".parse().unwrap(),)]
            );
        }
    }

    #[tokio::test]
    async fn watch_endpoints_for_clusters() {
        // Test that whenever we receive endpoint changes, we send back a new discovery request.

        let (cluster_updates_tx, _) = mpsc::channel::<ClusterState>(100);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cm = ClusterManager::new(logger(), cluster_updates_tx, discovery_req_tx);

        let names = vec!["a".into(), "b".into()];
        cm.on_cluster_response(cluster_discovery_response("3", "6", names.clone()))
            .await;

        let _ = recv_cluster_and_endpoint_reqs(&mut discovery_req_rx).await;

        let mut version = 4;
        let mut nonce = 9;
        for _ in 0..3 {
            // Send an endpoint update.
            cm.on_cluster_load_assignment_response(endpoint_discovery_response(
                &version.to_string(),
                &nonce.to_string(),
                names.clone(),
            ))
            .await;

            // Check that we send back an ACK request.
            let endpoint_req = discovery_req_rx.recv().await.unwrap();
            assert_ack_req(&endpoint_req);
            assert_req_contains_resource_names(&endpoint_req, &names);
            assert_req_version_and_nonce(&endpoint_req, &version.to_string(), &nonce.to_string());

            version += 1;
            nonce += 1;
        }
    }

    #[tokio::test]
    async fn nack_cluster_update() {
        // Test that if we receive a bad cluster update, we NACK.

        let (cluster_updates_tx, _) = mpsc::channel::<ClusterState>(100);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cm = ClusterManager::new(logger(), cluster_updates_tx, discovery_req_tx);

        let initial_names = vec!["a".into()];
        cm.on_cluster_response(cluster_discovery_response("1", "2", initial_names.clone()))
            .await;

        let _ = recv_cluster_and_endpoint_reqs(&mut discovery_req_rx).await;

        let bad_cluster_update = cluster_discovery_response_with_update(
            "1",
            "2",
            vec!["b".into(), "c".into(), "d".into()],
            |mut cluster| {
                if &cluster.name == "c" {
                    // discovery type is required so this update should be rejected.
                    cluster.cluster_discovery_type = None;
                }
                cluster
            },
        );

        cm.on_cluster_response(bad_cluster_update).await;
        assert_nack_req(&discovery_req_rx.recv().await.unwrap());
    }

    #[tokio::test]
    async fn nack_endpoint_update() {
        // Test that if we receive a bad endpoint update, we NACK.

        let (cluster_updates_tx, _) = mpsc::channel::<ClusterState>(100);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cm = ClusterManager::new(logger(), cluster_updates_tx, discovery_req_tx);

        cm.on_cluster_response(cluster_discovery_response(
            "1",
            "2",
            vec!["a".into(), "b".into(), "c".into(), "d".into()],
        ))
        .await;

        let _ = recv_cluster_and_endpoint_reqs(&mut discovery_req_rx).await;

        let bad_endpoint_update = endpoint_discovery_response_with_update(
            "9",
            "10",
            vec!["b".into(), "c".into(), "d".into()],
            |mut assignment| {
                if &assignment.cluster_name == "c" {
                    assignment.endpoints[0].lb_endpoints[0].host_identifier =
                        Some(HostIdentifier::Endpoint(Endpoint {
                            address: Some(Address {
                                address: Some(address::Address::SocketAddress(SocketAddress {
                                    protocol: 1,
                                    address: "127.0.0.1".into(),
                                    resolver_name: "".into(),
                                    ipv4_compat: true,
                                    // Bad port provided so we should reject the update.
                                    port_specifier: Some(PortSpecifier::NamedPort(
                                        "not_supported".into(),
                                    )),
                                })),
                            }),
                            health_check_config: None,
                            hostname: "".into(),
                        }));
                }
                assignment
            },
        );

        cm.on_cluster_load_assignment_response(bad_endpoint_update)
            .await;
        assert_nack_req(&discovery_req_rx.recv().await.unwrap());
    }

    #[tokio::test]
    async fn cluster_updates() {
        // Test that whenever we receive a cluster update, we send it downstream.

        let (cluster_updates_tx, mut cluster_updates_rx) = mpsc::channel::<ClusterState>(100);
        let (discovery_req_tx, _) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cm = ClusterManager::new(logger(), cluster_updates_tx, discovery_req_tx);

        cm.on_cluster_response(cluster_discovery_response(
            "1",
            "2",
            vec!["a".into(), "b".into()],
        ))
        .await;

        let cluster_state = cluster_updates_rx.recv().await.unwrap();
        assert_eq!(cluster_state.len(), 2);

        let cluster_a = cluster_state.get("a").unwrap();
        let cluster_b = cluster_state.get("b").unwrap();

        assert_cluster_has_lone_static_address(cluster_a, "127.0.0.1:2020");
        assert_cluster_has_lone_static_address(cluster_b, "127.0.0.1:2020");

        // Update one of the clusters and check that the new cluster set is sent downstream.
        cm.on_cluster_response(cluster_discovery_response_with_update(
            "3",
            "4",
            vec!["a".into(), "b".into()],
            |mut cluster| {
                if &cluster.name == "a" {
                    if let Some(assignment) = cluster.load_assignment.as_mut() {
                        assignment.endpoints[0].lb_endpoints[0].host_identifier =
                            Some(HostIdentifier::Endpoint(Endpoint {
                                address: Some(Address {
                                    address: Some(address::Address::SocketAddress(SocketAddress {
                                        protocol: 1,
                                        address: "127.0.0.10".into(),
                                        resolver_name: "".into(),
                                        ipv4_compat: true,
                                        port_specifier: Some(PortSpecifier::PortValue(3030)),
                                    })),
                                }),
                                health_check_config: None,
                                hostname: "".into(),
                            }))
                    };
                }
                cluster
            },
        ))
        .await;

        let cluster_state = cluster_updates_rx.recv().await.unwrap();
        assert_eq!(cluster_state.len(), 2);

        let cluster_a = cluster_state.get("a").unwrap();
        let cluster_b = cluster_state.get("b").unwrap();

        assert_cluster_has_lone_static_address(cluster_a, "127.0.0.10:3030");
        assert_cluster_has_lone_static_address(cluster_b, "127.0.0.1:2020");
    }

    #[tokio::test]
    async fn cluster_updates_for_endpoints() {
        // Test that whenever we receive an endpoint update, we send a new cluster set downstream.

        let (cluster_updates_tx, mut cluster_updates_rx) = mpsc::channel::<ClusterState>(100);
        let (discovery_req_tx, _) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cm = ClusterManager::new(logger(), cluster_updates_tx, discovery_req_tx);

        cm.on_cluster_response(cluster_discovery_response(
            "1",
            "2",
            vec!["a".into(), "b".into()],
        ))
        .await;

        // Read the cluster update.
        let cluster_state = cluster_updates_rx.recv().await.unwrap();
        assert_eq!(cluster_state.len(), 2);

        // Update one of the endpoints and check that a new cluster set is sent downstream.
        cm.on_cluster_load_assignment_response(endpoint_discovery_response_with_update(
            "3",
            "4",
            vec!["a".into(), "b".into()],
            |mut assignment| {
                if &assignment.cluster_name == "b" {
                    assignment.endpoints[0].lb_endpoints[0].host_identifier =
                        Some(HostIdentifier::Endpoint(Endpoint {
                            address: Some(Address {
                                address: Some(address::Address::SocketAddress(SocketAddress {
                                    protocol: 1,
                                    address: "127.0.0.9".into(),
                                    resolver_name: "".into(),
                                    ipv4_compat: true,
                                    port_specifier: Some(PortSpecifier::PortValue(4040)),
                                })),
                            }),
                            health_check_config: None,
                            hostname: "".into(),
                        }));
                }
                assignment
            },
        ))
        .await;

        let cluster_state = cluster_updates_rx.recv().await.unwrap();
        assert_eq!(cluster_state.len(), 2);

        let cluster_a = cluster_state.get("a").unwrap();
        let cluster_b = cluster_state.get("b").unwrap();

        assert_cluster_has_lone_static_address(cluster_a, "127.0.0.1:2020");
        assert_cluster_has_lone_static_address(cluster_b, "127.0.0.9:4040");
    }

    #[tokio::test]
    async fn endpoint_metadata() {
        // Test that we include associated endpoint metadata in cluster update.

        let (cluster_updates_tx, mut cluster_updates_rx) = mpsc::channel::<ClusterState>(100);
        let (discovery_req_tx, _) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cm = ClusterManager::new(logger(), cluster_updates_tx, discovery_req_tx);

        cm.on_cluster_response(cluster_discovery_response_with_update(
            "1",
            "2",
            vec!["a".into()],
            |mut cluster| {
                if let Some(assignment) = cluster.load_assignment.as_mut() {
                    // Set metadata mapping a key to an empty array.
                    assignment.endpoints[0].lb_endpoints[0].metadata = Some(Metadata {
                        filter_metadata: vec![(
                            format!("key-{}", cluster.name),
                            ProstStruct {
                                fields: vec![(
                                    "one".into(),
                                    ProstValue {
                                        kind: Some(Kind::StringValue("two".into())),
                                    },
                                )]
                                .into_iter()
                                .collect(),
                            },
                        )]
                        .into_iter()
                        .collect(),
                    })
                };

                cluster
            },
        ))
        .await;

        // Read the cluster update.
        let cluster_state = cluster_updates_rx.recv().await.unwrap();
        assert_eq!(cluster_state.len(), 1);
        let (cluster_name, cluster) = cluster_state.iter().next().unwrap();

        assert_eq!(cluster.localities.len(), 1);
        let (_, locality) = cluster.localities.iter().next().unwrap();

        // Validate the metadata we set for the endpoint.
        assert_eq!(locality.endpoints.len(), 1);
        let endpoint = locality.endpoints.get(0).unwrap();
        let dyn_metadata = &endpoint.metadata.unknown;

        assert_eq!(dyn_metadata.len(), 1);

        let value = dyn_metadata
            .get(&format!("key-{}", cluster_name).into())
            .unwrap();
        assert_eq!(
            value,
            &serde_yaml::Value::from(
                std::array::IntoIter::new([("one".into(), "two".into())])
                    .collect::<serde_yaml::Mapping>()
            )
        );
    }

    // Test Helpers
    fn create_endpoint_resource(cluster_name: &str) -> ClusterLoadAssignment {
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
                                address: "127.0.0.1".into(),
                                resolver_name: "".into(),
                                ipv4_compat: true,
                                port_specifier: Some(PortSpecifier::PortValue(2020)),
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
    fn create_cluster_resource(name: &str) -> Cluster {
        Cluster {
            name: name.into(),
            transport_socket_matches: vec![],
            alt_stat_name: "".into(),
            eds_cluster_config: None,
            connect_timeout: None,
            per_connection_buffer_limit_bytes: None,
            lb_policy: 0,
            load_balancing_policy: None,
            load_assignment: Some(create_endpoint_resource(name)),
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

    fn cluster_discovery_response(
        version_info: &str,
        nonce: &str,
        cluster_names: Vec<String>,
    ) -> DiscoveryResponse {
        cluster_discovery_response_with_update(version_info, nonce, cluster_names, |c| c)
    }

    fn cluster_discovery_response_with_update<F>(
        version_info: &str,
        nonce: &str,
        cluster_names: Vec<String>,
        update_fn: F,
    ) -> DiscoveryResponse
    where
        F: Fn(Cluster) -> Cluster,
    {
        let resources = cluster_names
            .into_iter()
            .map(|name| {
                let cluster = update_fn(create_cluster_resource(&name));
                let mut value = vec![];
                cluster.encode(&mut value).unwrap();
                prost_types::Any {
                    type_url: CLUSTER_TYPE.into(),
                    value,
                }
            })
            .collect();

        DiscoveryResponse {
            type_url: CLUSTER_TYPE.into(),
            version_info: version_info.into(),
            nonce: nonce.into(),
            resources,
            canary: false,
            control_plane: None,
        }
    }

    fn endpoint_discovery_response(
        version_info: &str,
        nonce: &str,
        cluster_names: Vec<String>,
    ) -> DiscoveryResponse {
        endpoint_discovery_response_with_update(version_info, nonce, cluster_names, |e| e)
    }

    fn endpoint_discovery_response_with_update<F>(
        version_info: &str,
        nonce: &str,
        cluster_names: Vec<String>,
        update_fn: F,
    ) -> DiscoveryResponse
    where
        F: Fn(ClusterLoadAssignment) -> ClusterLoadAssignment,
    {
        let resources = cluster_names
            .into_iter()
            .map(|name| {
                let endpoint = update_fn(create_endpoint_resource(&name));
                let mut value = vec![];
                endpoint.encode(&mut value).unwrap();
                prost_types::Any {
                    type_url: ENDPOINT_TYPE.into(),
                    value,
                }
            })
            .collect();

        DiscoveryResponse {
            type_url: ENDPOINT_TYPE.into(),
            version_info: version_info.into(),
            nonce: nonce.into(),
            resources,
            canary: false,
            control_plane: None,
        }
    }

    async fn recv_cluster_and_endpoint_reqs(
        discovery_req_rx: &mut mpsc::Receiver<DiscoveryRequest>,
    ) -> (DiscoveryRequest, DiscoveryRequest) {
        let a = discovery_req_rx.recv().await.unwrap();
        let b = discovery_req_rx.recv().await.unwrap();

        assert!(a.type_url == CLUSTER_TYPE || b.type_url == CLUSTER_TYPE);
        assert!(a.type_url == ENDPOINT_TYPE || b.type_url == ENDPOINT_TYPE);

        if a.type_url == CLUSTER_TYPE {
            (a, b)
        } else {
            (b, a)
        }
    }

    fn assert_nack_req(req: &DiscoveryRequest) {
        assert!(req.error_detail.is_some());
    }

    fn assert_ack_req(req: &DiscoveryRequest) {
        assert_eq!(req.error_detail, None);
    }

    fn assert_req_contains_resource_names(req: &DiscoveryRequest, expected_names: &[String]) {
        assert_eq!(
            expected_names.iter().cloned().collect::<HashSet<_>>(),
            req.resource_names.iter().cloned().collect::<HashSet<_>>()
        );
    }

    fn assert_req_version_and_nonce(req: &DiscoveryRequest, version_info: &str, nonce: &str) {
        assert_eq!(version_info, &req.version_info);
        assert_eq!(nonce, &req.response_nonce);
    }

    fn assert_cluster_has_lone_static_address(cluster: &ProxyCluster, expected_addr: &str) {
        assert_eq!(
            cluster.localities.get(&None).unwrap().endpoints[0].address,
            expected_addr.parse().unwrap()
        )
    }
}
