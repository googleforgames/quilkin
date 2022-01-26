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

mod downstream;
pub(super) mod metrics;
mod resource_manager;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;
use tracing::Instrument;

use crate::{
    cluster::cluster_manager::SharedClusterManager,
    filters::{manager::SharedFilterManager, FilterRegistry},
    proxy::{
        builder::{ValidatedConfig, ValidatedSource},
        sessions::{
            metrics::Metrics as SessionMetrics, session_manager::SessionManager, UpstreamPacket,
            SESSION_TIMEOUT_SECONDS,
        },
        Admin,
    },
    utils::debug,
    Result,
};

use super::metrics::Metrics;

use self::{
    downstream::{DownstreamPacket, DownstreamReceiveProcessor, DownstreamReceiveWorker},
    metrics::Metrics as ProxyMetrics,
    resource_manager::{DynamicResourceManagers, StaticResourceManagers},
};

/// Server is the UDP server main implementation
pub struct Server {
    // We use pub(super) to limit instantiation only to the Builder.
    pub(super) config: Arc<ValidatedConfig>,
    // Admin may be turned off, primarily for testing.
    pub(super) admin: Option<Admin>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) proxy_metrics: ProxyMetrics,
    pub(super) session_metrics: SessionMetrics,
    pub(super) filter_registry: FilterRegistry,
}

/// Represents arguments to the `Server::run_recv_from` method.
struct RunRecvFromArgs {
    cluster_manager: SharedClusterManager,
    filter_manager: SharedFilterManager,
    socket: Arc<UdpSocket>,
    session_manager: SessionManager,
    session_ttl: Duration,
    send_packets: mpsc::Sender<UpstreamPacket>,
    shutdown_rx: watch::Receiver<()>,
}

impl Server {
    /// start the async processing of incoming UDP packets. Will block until an
    /// event is sent through the stop Receiver.
    #[tracing::instrument(skip_all, level = "trace", fields(port = self.config.proxy.port, proxy_id = &*self.config.proxy.id))]
    pub async fn run(self, mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
        let socket = Arc::new(Server::bind(self.config.proxy.port).await?);
        let session_manager = SessionManager::new(shutdown_rx.clone());
        let (send_packets, receive_packets) = mpsc::channel::<UpstreamPacket>(1024);

        let session_ttl = Duration::from_secs(SESSION_TIMEOUT_SECONDS);

        let (cluster_manager, filter_manager) =
            self.create_resource_managers(shutdown_rx.clone()).await?;

        if let Some(admin) = &self.admin {
            admin.run(
                cluster_manager.clone(),
                filter_manager.clone(),
                shutdown_rx.clone(),
            );
        }

        tokio::spawn(Self::run_receive_packet(socket.clone(), receive_packets));
        let recv_loop = self.run_recv_from(RunRecvFromArgs {
            cluster_manager,
            filter_manager,
            socket,
            session_manager,
            session_ttl,
            send_packets,
            shutdown_rx: shutdown_rx.clone(),
        });

        tracing::info!("Quilkin is ready.");

        tokio::select! {
            join_result = recv_loop.instrument(tracing::trace_span!("Main recv loop")) => {
                join_result.map_err(|error| eyre::eyre!(error))
            }
            _ = shutdown_rx.changed() => {
                Ok(())
            }
        }
    }

    #[tracing::instrument(skip_all, level = "trace")]
    async fn create_resource_managers(
        &self,
        shutdown_rx: watch::Receiver<()>,
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
                .map_err(|err| {
                    eyre::eyre!(err).wrap_err("Failed to initialise static resource manager.")
                })?;
                Ok((manager.cluster_manager, manager.filter_manager))
            }
            ValidatedSource::Dynamic { management_servers } => {
                let manager = DynamicResourceManagers::new(
                    self.config.proxy.id.clone(),
                    self.metrics.registry.clone(),
                    self.filter_registry.clone(),
                    management_servers.to_vec(),
                    shutdown_rx,
                )
                .await
                .map_err(|err| {
                    eyre::eyre!(err).wrap_err("Failed to initialise xDS management servers.")
                })?;

                let execution_result_rx = manager.execution_result_rx;
                // Spawn a task to check for an error if the XDS client
                // terminates and forward the error upstream.
                tokio::spawn(async move {
                    if let Err(error) = execution_result_rx.await {
                        // TODO: For now only log the error but we would like to
                        //   initiate a shut down instead once this happens.
                        tracing::error!(
                            %error,
                            "ClusterManager XDS client terminated with an error"
                        );
                    }
                });

                Ok((manager.cluster_manager, manager.filter_manager))
            }
        }
    }

    /// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
    /// Each received packet is placed on a queue to be processed by a worker task.
    /// This function also spawns the set of worker tasks responsible for consuming packets
    /// off the aforementioned queue and processing them through the filter chain and session
    /// pipeline.
    #[tracing::instrument(skip_all, level = "trace")]
    fn run_recv_from(
        &self,
        args: RunRecvFromArgs,
    ) -> impl std::future::Future<Output = Result<()>> {
        let session_manager = args.session_manager;
        let proxy_metrics = self.proxy_metrics.clone();
        let session_metrics = self.session_metrics.clone();
        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = num_cpus::get();
        // Contains channel Senders for each worker task.
        let mut packet_txs = vec![];

        for worker_id in 0..num_workers {
            let (packet_tx, packet_rx) = mpsc::channel(num_workers);
            packet_txs.push(packet_tx);
            // Start the worker tasks that pick up received packets from their queue
            // and processes them.
            tokio::spawn(
                DownstreamReceiveWorker {
                    worker_id,
                    packet_rx,
                    shutdown_rx: args.shutdown_rx.clone(),
                    processor: DownstreamReceiveProcessor {
                        proxy_metrics: proxy_metrics.clone(),
                        session_metrics: session_metrics.clone(),
                        cluster_manager: args.cluster_manager.clone(),
                        filter_manager: args.filter_manager.clone(),
                        session_manager: session_manager.clone(),
                        session_ttl: args.session_ttl,
                        send_packets: args.send_packets.clone(),
                    },
                }
                .run(),
            );
        }

        // Start the background task to receive downstream packets from the socket
        // and place them onto the worker tasks' queue for processing.
        let socket = args.socket;

        async move {
            // Index to round-robin over workers to process packets.
            let mut next_worker = 0;
            let num_workers = num_workers;

            // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
            // packet, which is the maximum value of 16 a bit integer.
            let mut buf = vec![0; 1 << 16];
            loop {
                match socket
                    .recv_from(&mut buf)
                    .instrument(tracing::trace_span!("Received packet"))
                    .await
                {
                    Ok((size, recv_addr)) => {
                        let timer = proxy_metrics.read_processing_time_seconds.start_timer();
                        let packet_tx = &mut packet_txs[next_worker % num_workers];
                        next_worker += 1;

                        if packet_tx
                            .send(DownstreamPacket {
                                source: recv_addr.into(),
                                contents: (&buf[..size]).to_vec(),
                                timer,
                            })
                            .instrument(tracing::trace_span!("Sending downstream packet"))
                            .await
                            .is_err()
                        {
                            // We cannot recover from this error since
                            // it implies that the receiver has been dropped.
                            let error = eyre::eyre!(
                                "Failed to send received packet over channel to worker"
                            );
                            tracing::error!(%error);
                            return Err(error);
                        }
                    }
                    Err(error) => {
                        let error = eyre::eyre!(error).wrap_err("Error processing receive socket");
                        tracing::error!(%error);
                        return Err(error);
                    }
                }
            }
        }
    }

    /// run_receive_packet is a non-blocking loop on receive_packets.recv() channel
    /// and sends each packet on to the Packet.dest
    #[tracing::instrument(skip_all, level = "trace")]
    async fn run_receive_packet(
        socket: Arc<UdpSocket>,
        mut receive_packets: mpsc::Receiver<UpstreamPacket>,
    ) {
        while let Some(packet) = receive_packets
            .recv()
            .instrument(tracing::trace_span!("Receiving packet from origin"))
            .await
        {
            tracing::debug!(
                origin = %packet.dest(),
                contents = %debug::bytes_to_string(packet.contents()),
                "Sending packet back to origin"
            );

            let address = match packet.dest().to_socket_addr() {
                Ok(address) => address,
                Err(error) => {
                    tracing::error!(dest = %packet.dest(), %error, "Error resolving address");
                    continue;
                }
            };

            if let Err(error) = socket
                .send_to(packet.contents(), address)
                .instrument(tracing::trace_span!("send_to"))
                .await
            {
                tracing::error!(dest = %packet.dest(), %error, "Error sending packet");
            }
            packet.stop_and_record();
        }
    }

    /// bind binds the local configured port
    async fn bind(port: u16) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port);
        UdpSocket::bind(addr)
            .await
            .map_err(|error| eyre::eyre!(error))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use prometheus::{Histogram, HistogramOpts, Registry};
    use tokio::sync::mpsc;
    use tokio::time;
    use tokio::time::timeout;
    use tokio::time::Duration;

    use crate::cluster::cluster_manager::ClusterManager;
    use crate::config;
    use crate::config::Builder as ConfigBuilder;
    use crate::endpoint::{Endpoint, Endpoints};
    use crate::filters::{manager::FilterManager, FilterChain};
    use crate::proxy::sessions::UpstreamPacket;
    use crate::proxy::Builder;
    use crate::test_utils::{config_with_dummy_endpoint, new_registry, new_test_chain, TestHelper};

    use super::*;

    #[tokio::test]
    async fn run_server() {
        let mut t = TestHelper::default();

        let endpoint1 = t.open_socket_and_recv_single_packet().await;
        let endpoint2 = t.open_socket_and_recv_single_packet().await;

        let local_addr = (Ipv4Addr::UNSPECIFIED, 12358);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.1)
            .with_static(
                vec![],
                vec![
                    Endpoint::new(endpoint1.socket.local_addr().unwrap().into()),
                    Endpoint::new(endpoint2.socket.local_addr().unwrap().into()),
                ],
            )
            .build();
        t.run_server_with_config(config);

        let msg = "hello";
        endpoint1
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(msg, endpoint1.packet_rx.await.unwrap());
        assert_eq!(msg, endpoint2.packet_rx.await.unwrap());
    }

    #[tokio::test]
    async fn run_client() {
        let mut t = TestHelper::default();

        let endpoint = t.open_socket_and_recv_single_packet().await;

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(
                vec![],
                vec![Endpoint::new(endpoint.socket.local_addr().unwrap().into())],
            )
            .build();
        t.run_server_with_config(config);

        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(msg, endpoint.packet_rx.await.unwrap());
    }

    #[tokio::test]
    async fn run_with_filter() {
        let mut t = TestHelper::default();

        let registry = new_registry();
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12367);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(
                vec![config::Filter {
                    name: "TestFilter".to_string(),
                    config: None,
                }],
                vec![Endpoint::new(endpoint.socket.local_addr().unwrap().into())],
            )
            .build();
        t.run_server_with_builder(
            Builder::from(Arc::new(config))
                .with_filter_registry(registry)
                .disable_admin(),
        );

        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();

        // since we don't know what the session ephemeral port is, we'll just
        // search for the filter strings.
        let result = endpoint.packet_rx.await.unwrap();
        assert!(result.contains(msg), "'{}' not found in '{}'", msg, result);
        assert!(result.contains(":odr:"), ":odr: not found in '{}'", result);
    }

    #[tokio::test]
    async fn bind() {
        let socket = Server::bind(12345).await.unwrap();
        let addr = socket.local_addr().unwrap();

        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12345);
        assert_eq!(expected, addr)
    }

    #[tokio::test]
    async fn spawn_downstream_receive_workers() {
        time::pause();

        struct Result {
            msg: String,
            addr: SocketAddr,
        }
        struct Expected {
            session_len: usize,
        }

        async fn test(
            name: String,
            chain: Arc<FilterChain>,
            expected: Expected,
            registry: &prometheus::Registry,
            shutdown_rx: watch::Receiver<()>,
        ) -> Result {
            let t = TestHelper::default();

            tracing::info!(%name, "Test");
            let msg = "hello".to_string();
            let endpoint = t.open_socket_and_recv_single_packet().await;

            let socket = t.create_socket().await;
            let mut receive_addr = socket.local_addr().unwrap();
            // need to switch to 127.0.0.1, as the request comes locally
            receive_addr.set_ip("127.0.0.1".parse().unwrap());

            let session_manager = SessionManager::new(shutdown_rx.clone());
            let (send_packets, mut recv_packets) = mpsc::channel::<UpstreamPacket>(1);

            let time_increment = 10;
            time::advance(Duration::from_secs(time_increment)).await;

            let endpoint_address = endpoint.socket.local_addr().unwrap().into();

            let num_workers = 2;
            let mut packet_txs = Vec::with_capacity(num_workers);

            let cluster_manager = ClusterManager::fixed(
                registry,
                Endpoints::new(vec![Endpoint::new(endpoint_address)]).unwrap(),
            )
            .unwrap();
            let filter_manager = FilterManager::fixed(chain.clone());
            let metrics = Arc::new(Metrics::new(registry.clone()));
            let proxy_metrics = ProxyMetrics::new(&metrics.registry).unwrap();

            for worker_id in 0..num_workers {
                let (packet_tx, packet_rx) = mpsc::channel(num_workers);
                packet_txs.push(packet_tx);

                let proxy_metrics = proxy_metrics.clone();
                let session_metrics = SessionMetrics::new(&metrics.registry).unwrap();

                tokio::spawn(
                    DownstreamReceiveWorker {
                        worker_id,
                        packet_rx,
                        shutdown_rx: shutdown_rx.clone(),
                        processor: DownstreamReceiveProcessor {
                            proxy_metrics: proxy_metrics.clone(),
                            session_metrics,
                            cluster_manager: cluster_manager.clone(),
                            filter_manager: filter_manager.clone(),
                            session_manager: session_manager.clone(),
                            session_ttl: Duration::from_secs(10),
                            send_packets: send_packets.clone(),
                        },
                    }
                    .run(),
                );
            }

            for packet_tx in packet_txs {
                packet_tx
                    .send(DownstreamPacket {
                        source: receive_addr.into(),
                        contents: msg.as_bytes().to_vec(),
                        timer: proxy_metrics.read_processing_time_seconds.start_timer(),
                    })
                    .await
                    .unwrap();
            }

            socket.send_to(msg.as_bytes(), &receive_addr).await.unwrap();

            let result = endpoint.packet_rx.await.unwrap();
            recv_packets.close();

            let map = session_manager.get_sessions().await;
            assert_eq!(expected.session_len, map.len());
            let build_key = (
                receive_addr.into(),
                endpoint.socket.local_addr().unwrap().into(),
            )
                .into();
            assert!(map.contains_key(&build_key));
            let session = map.get(&build_key).unwrap();
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let diff = session.expiration() - now_secs;
            assert!((5..11).contains(&diff));

            assert_eq!(
                num_workers as u64,
                proxy_metrics
                    .read_processing_time_seconds
                    .get_sample_count(),
                "One packet is sent for each worker, and we should have a sample for each"
            );

            Result {
                msg: result,
                addr: receive_addr,
            }
        }

        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let registry = Registry::default();
        let chain = Arc::new(FilterChain::new(vec![], &registry).unwrap());
        let result = test(
            "no filter".to_string(),
            chain,
            Expected { session_len: 1 },
            &registry,
            shutdown_rx.clone(),
        )
        .await;
        assert_eq!("hello", result.msg);

        let chain = new_test_chain(&registry);
        let result = test(
            "test filter".to_string(),
            chain,
            Expected { session_len: 1 },
            &registry,
            shutdown_rx.clone(),
        )
        .await;

        assert_eq!(
            format!("hello:odr:127.0.0.1:{}", result.addr.port(),),
            result.msg
        );

        time::resume();
    }

    #[tokio::test]
    async fn run_recv_from() {
        let t = TestHelper::default();
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        let msg = "hello";
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let socket = t.create_socket().await;
        let session_manager = SessionManager::new(shutdown_rx.clone());
        let (send_packets, mut recv_packets) = mpsc::channel::<UpstreamPacket>(1);

        let config = Arc::new(config_with_dummy_endpoint().build());
        let server = Builder::from(config).validate().unwrap().build();
        let registry = Registry::default();

        tokio::spawn(
            server.run_recv_from(RunRecvFromArgs {
                cluster_manager: ClusterManager::fixed(
                    &registry,
                    Endpoints::new(vec![Endpoint::new(
                        endpoint.socket.local_addr().unwrap().into(),
                    )])
                    .unwrap(),
                )
                .unwrap(),
                filter_manager: FilterManager::fixed(Arc::new(
                    FilterChain::new(vec![], &registry).unwrap(),
                )),
                socket: socket.clone(),
                session_manager: session_manager.clone(),
                session_ttl: Duration::from_secs(10),
                send_packets,
                shutdown_rx,
            }),
        );

        let addr = socket.local_addr().unwrap();
        socket.send_to(msg.as_bytes(), &addr).await.unwrap();

        assert_eq!(
            msg,
            timeout(Duration::from_millis(500), endpoint.packet_rx)
                .await
                .expect("should get a packet")
                .unwrap()
        );
        recv_packets.close();
    }

    #[tokio::test]
    async fn run_receive_packet() {
        let t = TestHelper::default();

        let histogram = Histogram::with_opts(HistogramOpts::new("test", "test")).unwrap();

        let msg = "hello";

        // without a filter
        let (send_packet, recv_packet) = mpsc::channel::<UpstreamPacket>(1);
        let endpoint = t.open_socket_and_recv_single_packet().await;
        if send_packet
            .send(UpstreamPacket::new(
                endpoint.socket.local_addr().unwrap().into(),
                msg.as_bytes().to_vec(),
                histogram.start_timer(),
            ))
            .await
            .is_err()
        {
            unreachable!("failed to send packet over channel");
        }
        let config = Arc::new(config_with_dummy_endpoint().build());
        let _server = Builder::from(config).validate().unwrap().build();
        tokio::spawn(Server::run_receive_packet(endpoint.socket, recv_packet));
        assert_eq!(msg, endpoint.packet_rx.await.unwrap());
        assert_eq!(
            1_u64,
            histogram.get_sample_count(),
            "one packet sent, so there should be one sample"
        );
    }
}
