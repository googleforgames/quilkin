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

mod admin;
mod builder;
mod health;
mod metrics;
mod pipeline;

mod resource_manager;

pub mod error;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use slog::{error, info, Logger};
use tokio::{net::UdpSocket, sync::watch};

use crate::{
    cluster::cluster_manager::SharedClusterManager,
    filters::{manager::SharedFilterManager, FilterRegistry},
};

use self::{
    builder::{ValidatedConfig, ValidatedSource},
    error::Error,
    metrics::ProxyMetrics,
    pipeline::{Pipeline, UpstreamMetrics},
    resource_manager::{DynamicResourceManagers, StaticResourceManagers},
};

pub(crate) use self::{admin::Admin, health::Health, metrics::Metrics};

pub use builder::{logger, Builder, PendingValidation, Validated};

type Result<T, E = Error> = std::result::Result<T, E>;
pub type ShutdownRx = watch::Receiver<()>;

/// Responsible for managing all of the individual components in Quilkin, such
/// as its configuration, administration interface, data pipeline, etc.
pub struct Proxy {
    log: Logger,
    config: Arc<ValidatedConfig>,
    // Admin may be turned off, primarily for testing.
    admin: Option<Admin>,
    metrics: Arc<Metrics>,
    proxy_metrics: ProxyMetrics,
    upstream_metrics: UpstreamMetrics,
    filter_registry: FilterRegistry,
}

impl Proxy {
    /// Begins a new instance of `Proxy` and spawns each of its components in
    /// the background, it will run forever, until it encounters an error in the
    /// data pipeline, or until it receives a shutdown signal
    /// from `shutdown_rx`.
    pub async fn run(self, mut shutdown_rx: ShutdownRx) -> Result<()> {
        info!(self.log, "Starting"; "port" => self.config.proxy.port);
        let (cluster_manager, filter_manager) =
            self.create_resource_managers(shutdown_rx.clone()).await?;

        if let Some(admin) = self.admin {
            admin.spawn(self.metrics.clone(), shutdown_rx.clone());
        }

        let (upstream, downstream) = Pipeline {
            log: self.log.clone(),
            proxy_metrics: self.proxy_metrics,
            upstream_metrics: self.upstream_metrics,
            cluster_manager,
            filter_manager,
            downstream_socket: Self::bind(self.config.proxy.port).await.map(Arc::new)?,
        }
        .spawn(shutdown_rx.clone());

        tokio::select! {
            join_result = upstream => {
                join_result
                    .map_err(|join_err| Error::RecvLoop(format!("{}", join_err)))
                    .and_then(|x| x.map_err(Error::Upstream))
            }
            join_result = downstream => {
                join_result
                    .map_err(|join_err| Error::RecvLoop(format!("{}", join_err)))
                    .and_then(|inner| inner.map_err(Error::RecvLoop))
            }
            _ = shutdown_rx.changed() => {
                Ok(())
            }
        }
    }

    async fn create_resource_managers(
        &self,
        shutdown_rx: ShutdownRx,
    ) -> Result<(SharedClusterManager, SharedFilterManager)> {
        match &self.config.source {
            ValidatedSource::Static {
                filter_chain,
                endpoints,
            } => {
                let manager = StaticResourceManagers::new(
                    &self.metrics.registry,
                    endpoints.clone(),
                    filter_chain.clone(),
                )
                .map_err(|err| Error::Initialize(format!("{}", err)))?;
                Ok((manager.cluster_manager, manager.filter_manager))
            }
            ValidatedSource::Dynamic { management_servers } => {
                let manager = DynamicResourceManagers::new(
                    self.log.clone(),
                    self.config.proxy.id.clone(),
                    self.metrics.registry.clone(),
                    self.filter_registry.clone(),
                    management_servers.to_vec(),
                    shutdown_rx,
                )
                .await
                .map_err(|err| Error::Initialize(format!("{}", err)))?;

                let execution_result_rx = manager.execution_result_rx;
                // Spawn a task to check for an error if the XDS client
                // terminates and forward the error upstream.
                let log = self.log.clone();
                tokio::spawn(async move {
                    if let Err(err) = execution_result_rx.await {
                        // TODO: For now only log the error but we would like to
                        //   initiate a shut down instead once this happens.
                        error!(
                            log,
                            "ClusterManager XDS client terminated with an error: {}", err
                        );
                    }
                });

                Ok((manager.cluster_manager, manager.filter_manager))
            }
        }
    }

    /// bind binds the local configured port
    async fn bind(port: u16) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port);
        UdpSocket::bind(addr).await.map_err(Error::Bind)
    }
}

// #[cfg(test)]
// mod tests {
//     use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//     use std::sync::Arc;
//     use std::time::{SystemTime, UNIX_EPOCH};
//
//     use prometheus::Registry;
//     use slog::info;
//     use tokio::sync::mpsc;
//     use tokio::time;
//     use tokio::time::timeout;
//     use tokio::time::Duration;
//
//     use crate::cluster::cluster_manager::ClusterManager;
//     use crate::config;
//     use crate::config::{Builder as ConfigBuilder, EndPoint, Endpoints};
//     use crate::filters::{manager::FilterManager, FilterChain};
//     use crate::proxy::sessions::Packet;
//     use crate::proxy::Builder;
//     use crate::test_utils::{
//         config_with_dummy_endpoint, logger, new_registry, new_test_chain, TestHelper,
//     };
//
//     use super::*;
//
//     #[tokio::test]
//     async fn run_server() {
//         let mut t = TestHelper::default();
//
//         let endpoint1 = t.open_socket_and_recv_single_packet().await;
//         let endpoint2 = t.open_socket_and_recv_single_packet().await;
//
//         let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12358);
//         let config = ConfigBuilder::empty()
//             .with_port(local_addr.port())
//             .with_static(
//                 vec![],
//                 vec![
//                     EndPoint::new(endpoint1.socket.local_addr().unwrap()),
//                     EndPoint::new(endpoint2.socket.local_addr().unwrap()),
//                 ],
//             )
//             .build();
//         t.run_server_with_config(config);
//
//         let msg = "hello";
//         endpoint1
//             .socket
//             .send_to(msg.as_bytes(), &local_addr)
//             .await
//             .unwrap();
//         assert_eq!(msg, endpoint1.packet_rx.await.unwrap());
//         assert_eq!(msg, endpoint2.packet_rx.await.unwrap());
//     }
//
//     #[tokio::test]
//     async fn run_client() {
//         let mut t = TestHelper::default();
//
//         let endpoint = t.open_socket_and_recv_single_packet().await;
//
//         let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357);
//         let config = ConfigBuilder::empty()
//             .with_port(local_addr.port())
//             .with_static(
//                 vec![],
//                 vec![EndPoint::new(endpoint.socket.local_addr().unwrap())],
//             )
//             .build();
//         t.run_server_with_config(config);
//
//         let msg = "hello";
//         endpoint
//             .socket
//             .send_to(msg.as_bytes(), &local_addr)
//             .await
//             .unwrap();
//         assert_eq!(msg, endpoint.packet_rx.await.unwrap());
//     }
//
//     #[tokio::test]
//     async fn run_with_filter() {
//         let mut t = TestHelper::default();
//
//         let registry = new_registry(&logger());
//         let endpoint = t.open_socket_and_recv_single_packet().await;
//         let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12367);
//         let config = ConfigBuilder::empty()
//             .with_port(local_addr.port())
//             .with_static(
//                 vec![config::Filter {
//                     name: "TestFilter".to_string(),
//                     config: None,
//                 }],
//                 vec![EndPoint::new(endpoint.socket.local_addr().unwrap())],
//             )
//             .build();
//         t.run_server_with_builder(
//             Builder::from(Arc::new(config))
//                 .with_filter_registry(registry)
//                 .disable_admin(),
//         );
//
//         let msg = "hello";
//         endpoint
//             .socket
//             .send_to(msg.as_bytes(), &local_addr)
//             .await
//             .unwrap();
//
//         // since we don't know what the session ephemeral port is, we'll just
//         // search for the filter strings.
//         let result = endpoint.packet_rx.await.unwrap();
//         assert!(result.contains(msg), "'{}' not found in '{}'", msg, result);
//         assert!(result.contains(":odr:"), ":odr: not found in '{}'", result);
//     }
//
//     #[tokio::test]
//     async fn spawn_downstream_receive_workers() {
//         time::pause();
//
//         struct Result {
//             msg: String,
//             addr: SocketAddr,
//         }
//         struct Expected {
//             session_len: usize,
//         }
//
//         async fn test(
//             name: String,
//             chain: Arc<FilterChain>,
//             expected: Expected,
//             registry: &prometheus::Registry,
//             shutdown_rx: ShutdownRx,
//         ) -> Result {
//             let t = TestHelper::default();
//             let (emitter, _queue) =
//                 crate::filters::events::event_queue(crate::test_utils::logger());
//
//             info!(t.log, "Test"; "name" => name);
//             let msg = "hello".to_string();
//             let endpoint = t.open_socket_and_recv_single_packet().await;
//
//             let socket = t.create_socket().await;
//             let mut receive_addr = socket.local_addr().unwrap();
//             // need to switch to 127.0.0.1, as the request comes locally
//             receive_addr.set_ip("127.0.0.1".parse().unwrap());
//
//             let session_manager = SessionManager::new(t.log.clone(), shutdown_rx.clone());
//             let (send_packets, mut recv_packets) = mpsc::channel::<Packet>(1);
//
//             let time_increment = 10;
//             time::advance(Duration::from_secs(time_increment)).await;
//
//             let endpoint_address = endpoint.socket.local_addr().unwrap();
//
//             let num_workers = 2;
//             let mut packet_txs = Vec::with_capacity(num_workers);
//             let mut worker_configs = Vec::with_capacity(num_workers);
//
//             let cluster_manager = ClusterManager::fixed(
//                 registry,
//                 Endpoints::new(vec![Endpoint::from_address(endpoint_address)]).unwrap(),
//             )
//             .unwrap();
//             let filter_manager = FilterManager::fixed(chain.clone());
//
//             socket.send_to(msg.as_bytes(), &receive_addr).await.unwrap();
//
//             let build_key = (receive_addr, endpoint.socket.local_addr().unwrap());
//             assert!(map.contains_key(&build_key));
//             let session = map.get(&build_key).unwrap();
//             let now_secs = SystemTime::now()
//                 .duration_since(UNIX_EPOCH)
//                 .unwrap()
//                 .as_secs();
//             let diff = session.expiration() - now_secs;
//             assert!((5..11).contains(&diff));
//
//             Result {
//                 msg: result,
//                 addr: receive_addr,
//             }
//         }
//
//         let (_shutdown_tx, shutdown_rx) = watch::channel(());
//         let registry = Registry::default();
//         let chain = Arc::new(FilterChain::new(vec![], &registry).unwrap());
//         let result = test(
//             "no filter".to_string(),
//             chain,
//             Expected { session_len: 1 },
//             &registry,
//             shutdown_rx.clone(),
//         )
//         .await;
//         assert_eq!("hello", result.msg);
//
//         let chain = new_test_chain(&registry);
//         let result = test(
//             "test filter".to_string(),
//             chain,
//             Expected { session_len: 1 },
//             &registry,
//             shutdown_rx.clone(),
//         )
//         .await;
//
//         assert_eq!(
//             format!("hello:odr:127.0.0.1:{}", result.addr.port(),),
//             result.msg
//         );
//
//         time::resume();
//     }
//
//     #[tokio::test]
//     async fn run_recv_from() {
//         let t = TestHelper::default();
//         let (_shutdown_tx, shutdown_rx) = watch::channel(());
//
//         let msg = "hello";
//         let endpoint = t.open_socket_and_recv_single_packet().await;
//         let socket = t.create_socket().await;
//         let session_manager = SessionManager::new(t.log.clone(), shutdown_rx.clone());
//         let (send_packets, mut recv_packets) = mpsc::channel::<Packet>(1);
//
//         let config = Arc::new(config_with_dummy_endpoint().build());
//         let server = Builder::from(config).validate().unwrap().build();
//         let registry = Registry::default();
//
//         server.run_recv_from(RunRecvFromArgs {
//             cluster_manager: ClusterManager::fixed(
//                 &registry,
//                 Endpoints::new(vec![Endpoint::from_address(
//                     endpoint.socket.local_addr().unwrap(),
//                 )])
//                 .unwrap(),
//             )
//             .unwrap(),
//             filter_manager: FilterManager::fixed(Arc::new(
//                 FilterChain::new(vec![], &registry).unwrap(),
//             )),
//             socket: socket.clone(),
//             session_manager: session_manager.clone(),
//             session_ttl: Duration::from_secs(10),
//             send_packets,
//             shutdown_rx,
//         });
//
//         let addr = socket.local_addr().unwrap();
//         socket.send_to(msg.as_bytes(), &addr).await.unwrap();
//
//         assert_eq!(
//             msg,
//             timeout(Duration::from_millis(500), endpoint.packet_rx)
//                 .await
//                 .expect("should get a packet")
//                 .unwrap()
//         );
//         recv_packets.close();
//     }
//
//     #[tokio::test]
//     async fn run_receive_packet() {
//         let t = TestHelper::default();
//
//         let msg = "hello";
//
//         // without a filter
//         let (send_packet, recv_packet) = mpsc::channel::<Packet>(1);
//         let endpoint = t.open_socket_and_recv_single_packet().await;
//         if send_packet
//             .send(Packet::new(
//                 endpoint.socket.local_addr().unwrap(),
//                 msg.as_bytes().to_vec(),
//             ))
//             .await
//             .is_err()
//         {
//             unreachable!("failed to send packet over channel");
//         }
//         let config = Arc::new(config_with_dummy_endpoint().build());
//         let server = Builder::from(config).validate().unwrap().build();
//         server.run_receive_packet(endpoint.socket, recv_packet);
//         assert_eq!(msg, endpoint.packet_rx.await.unwrap());
//     }
// }
