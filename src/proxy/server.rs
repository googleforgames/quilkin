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

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use prometheus::HistogramTimer;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;

use metrics::Metrics as ProxyMetrics;

use crate::utils::net;
use crate::{
    cluster::SharedCluster,
    config::Config,
    endpoint::{Endpoint, EndpointAddress},
    filters::{Filter, ReadContext, SharedFilterChain},
    proxy::{
        sessions::{
            metrics::Metrics as SessionMetrics, session_manager::SessionManager, Session,
            SessionArgs, SessionKey, UpstreamPacket, SESSION_TIMEOUT_SECONDS,
        },
        Admin,
    },
    utils::debug,
    Result,
};

pub(super) mod metrics;

/// Server is the UDP server main implementation
pub struct Server {
    config: Arc<Config>,
    proxy_metrics: ProxyMetrics,
    session_metrics: SessionMetrics,
}

impl TryFrom<Config> for Server {
    type Error = eyre::Error;
    fn try_from(config: Config) -> Result<Self, Self::Error> {
        Ok(Self {
            config: Arc::from(config),
            proxy_metrics: ProxyMetrics::new()?,
            session_metrics: SessionMetrics::new()?,
        })
    }
}

/// Represents arguments to the `Server::run_recv_from` method.
struct RunRecvFromArgs {
    cluster: SharedCluster,
    filter_chain: SharedFilterChain,
    session_manager: SessionManager,
    session_ttl: Duration,
    send_packets: mpsc::Sender<UpstreamPacket>,
    shutdown_rx: watch::Receiver<()>,
}

/// Packet received from local port
#[derive(Debug)]
struct DownstreamPacket {
    source: EndpointAddress,
    contents: Vec<u8>,
    timer: HistogramTimer,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
struct DownstreamReceiveWorkerConfig {
    /// ID of the worker.
    worker_id: usize,
    /// Socket with reused port from which the worker receives packets.
    socket: UdpSocket,
    /// Configuration required to process a received downstream packet.
    receive_config: ProcessDownstreamReceiveConfig,
    /// The worker task exits when a value is received from this shutdown channel.
    shutdown_rx: watch::Receiver<()>,
}

/// Contains arguments to process a received downstream packet, through the
/// filter chain and session pipeline.
struct ProcessDownstreamReceiveConfig {
    proxy_metrics: ProxyMetrics,
    session_metrics: SessionMetrics,
    cluster: SharedCluster,
    filter_chain: SharedFilterChain,
    session_manager: SessionManager,
    session_ttl: Duration,
    send_packets: mpsc::Sender<UpstreamPacket>,
}

impl Server {
    /// Returns a builder for configuring a Quilkin Server.
    pub fn builder() -> crate::config::Builder {
        <_>::default()
    }

    /// start the async processing of incoming UDP packets. Will block until an
    /// event is sent through the stop Receiver.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
        tracing::info!(
            port = self.config.proxy.port,
            proxy_id = &*self.config.proxy.id,
            "Starting"
        );

        let socket = Arc::new(self.bind().await?);
        let session_manager = SessionManager::new(shutdown_rx.clone());
        let (send_packets, receive_packets) = mpsc::channel::<UpstreamPacket>(1024);

        let session_ttl = Duration::from_secs(SESSION_TIMEOUT_SECONDS);

        let (cluster, filter_chain) = self.create_resource_managers(shutdown_rx.clone())?;

        if let Some(admin) = self.config.admin.clone() {
            let admin = Admin::from(admin);
            admin.run(cluster.clone(), filter_chain.clone(), shutdown_rx.clone());
        }

        self.run_receive_packet(socket.clone(), receive_packets);
        self.run_recv_from(RunRecvFromArgs {
            cluster,
            filter_chain,
            session_manager,
            session_ttl,
            send_packets,
            shutdown_rx: shutdown_rx.clone(),
        })
        .await?;
        tracing::info!("Quilkin is ready");

        shutdown_rx
            .changed()
            .await
            .map_err(|error| eyre::eyre!(error))
    }

    fn create_resource_managers(
        &self,
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<(SharedCluster, SharedFilterChain)> {
        let cluster = SharedCluster::new_static_cluster(self.config.endpoints.load().to_vec())?;
        let filter_chain = SharedFilterChain::try_from(&***self.config.filters.load())?;

        let management_servers = self.config.management_servers.load_full();

        if !management_servers.is_empty() {
            let client = crate::xds::AdsClient::new()?;

            tokio::spawn(client.run(
                self.config.proxy.id.clone(),
                cluster.clone(),
                management_servers,
                filter_chain.clone(),
                shutdown_rx,
            ));
        }

        Ok((cluster, filter_chain))
    }

    /// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
    /// Each received packet is placed on a queue to be processed by a worker task.
    /// This function also spawns the set of worker tasks responsible for consuming packets
    /// off the aforementioned queue and processing them through the filter chain and session
    /// pipeline.
    async fn run_recv_from(&self, args: RunRecvFromArgs) -> Result<()> {
        let session_manager = args.session_manager;
        let proxy_metrics = self.proxy_metrics.clone();
        let session_metrics = self.session_metrics.clone();

        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = num_cpus::get();

        // TOXO: is this config setup still necessary? Maybe?
        // Contains config for each worker task.
        let mut worker_configs = vec![];
        for worker_id in 0..num_workers {
            let socket = self.bind().await?;
            worker_configs.push(DownstreamReceiveWorkerConfig {
                worker_id,
                socket,
                shutdown_rx: args.shutdown_rx.clone(),
                receive_config: ProcessDownstreamReceiveConfig {
                    proxy_metrics: proxy_metrics.clone(),
                    session_metrics: session_metrics.clone(),
                    cluster: args.cluster.clone(),
                    filter_chain: args.filter_chain.clone(),
                    session_manager: session_manager.clone(),
                    session_ttl: args.session_ttl,
                    send_packets: args.send_packets.clone(),
                },
            })
        }

        // Start the worker tasks that pick up received packets from their queue
        // and processes them.
        Self::spawn_downstream_receive_workers(worker_configs);
        Ok(())
    }

    // For each worker config provided, spawn a background task that sits in a
    // loop, receiving packets from a queue and processing them through
    // the filter chain.
    fn spawn_downstream_receive_workers(worker_configs: Vec<DownstreamReceiveWorkerConfig>) {
        for DownstreamReceiveWorkerConfig {
            worker_id,
            socket,
            mut shutdown_rx,
            receive_config,
        } in worker_configs
        {
            tokio::spawn(async move {
                // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
                // packet, which is the maximum value of 16 a bit integer.
                let mut buf = vec![0; 1 << 16];
                loop {
                    tracing::debug!(
                        id = worker_id,
                        addr = ?socket.local_addr(),
                        "Awaiting packet"
                    );
                    tokio::select! {
                        recv = socket.recv_from(&mut buf) => {
                            let timer = receive_config.proxy_metrics.read_processing_time_seconds.start_timer();
                            match recv {
                                Ok((size, source)) => {
                                    tracing::debug!(id = worker_id, size = size, source = %source, "Received packet");
                                    let packet = DownstreamPacket {
                                        source: source.into(),
                                        contents: (&buf[..size]).to_vec(),
                                        timer,
                                    };
                                    Self::process_downstream_received_packet(packet, &receive_config).await
                                },
                                Err(error) => {
                                    tracing::error!(%error);
                                    return;
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            tracing::debug!(id = worker_id, "Received shutdown signal");
                            return;
                        }
                    }
                }
            });
        }
    }

    /// Processes a packet by running it through the filter chain.
    async fn process_downstream_received_packet(
        packet: DownstreamPacket,
        args: &ProcessDownstreamReceiveConfig,
    ) {
        tracing::trace!(
            source = %packet.source,
            contents = %debug::bytes_to_string(&packet.contents),
            "Packet Received"
        );

        let endpoints = match args.cluster.endpoints() {
            Some(endpoints) => endpoints,
            None => {
                args.proxy_metrics.packets_dropped_no_endpoints.inc();
                return;
            }
        };

        let result = args.filter_chain.read(ReadContext::new(
            endpoints,
            packet.source.clone(),
            packet.contents,
        ));

        if let Some(response) = result {
            for endpoint in response.endpoints.iter() {
                Self::session_send_packet(
                    &response.contents,
                    packet.source.clone(),
                    endpoint,
                    args,
                )
                .await;
            }
        }
        packet.timer.stop_and_record();
    }

    /// Send a packet received from `recv_addr` to an endpoint.
    async fn session_send_packet(
        packet: &[u8],
        recv_addr: EndpointAddress,
        endpoint: &Endpoint,
        args: &ProcessDownstreamReceiveConfig,
    ) {
        let session_key = SessionKey {
            source: recv_addr,
            dest: endpoint.address.clone(),
        };

        // Grab a read lock and find the session.
        let guard = args.session_manager.get_sessions().await;
        if let Some(session) = guard.get(&session_key) {
            // If it exists then send the packet, we're done.
            Self::session_send_packet_helper(session, packet, args.session_ttl).await
        } else {
            // If it does not exist, grab a write lock so that we can create it.
            //
            // NOTE: We must drop the lock guard to release the lock before
            // trying to acquire a write lock since these lock aren't reentrant,
            // otherwise we will deadlock with our self.
            drop(guard);

            // Grab a write lock.
            let mut guard = args.session_manager.get_sessions_mut().await;

            // Although we have the write lock now, check whether some other thread
            // managed to create the session in-between our dropping the read
            // lock and grabbing the write lock.
            if let Some(session) = guard.get(&session_key) {
                // If the session now exists then we have less work to do,
                // simply send the packet.
                Self::session_send_packet_helper(session, packet, args.session_ttl).await;
            } else {
                // Otherwise, create the session and insert into the map.
                let session_args = SessionArgs {
                    metrics: args.session_metrics.clone(),
                    proxy_metrics: args.proxy_metrics.clone(),
                    filter_chain: args.filter_chain.clone(),
                    source: session_key.source.clone(),
                    dest: endpoint.clone(),
                    sender: args.send_packets.clone(),
                    ttl: args.session_ttl,
                };
                match session_args.into_session().await {
                    Ok(session) => {
                        // Insert the session into the map and release the write lock
                        // immediately since we don't want to block other threads while we send
                        // the packet. Instead, re-acquire a read lock and send the packet.
                        guard.insert(session.key(), session);

                        // Release the write lock.
                        drop(guard);

                        // Grab a read lock to send the packet.
                        let guard = args.session_manager.get_sessions().await;
                        if let Some(session) = guard.get(&session_key) {
                            Self::session_send_packet_helper(session, packet, args.session_ttl)
                                .await;
                        } else {
                            tracing::warn!(
                                key = %format!("({}:{})", session_key.source, session_key.dest),
                                "Could not find session"
                            )
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "Failed to ensure session exists");
                    }
                }
            }
        }
    }

    // A helper function to push a session's packet on its socket.
    async fn session_send_packet_helper(session: &Session, packet: &[u8], ttl: Duration) {
        match session.send(packet).await {
            Ok(_) => {
                if let Err(error) = session.update_expiration(ttl) {
                    tracing::warn!(%error, "Error updating session expiration")
                }
            }
            Err(error) => tracing::error!(%error, "Error sending packet from session"),
        };
    }

    /// run_receive_packet is a non-blocking loop on receive_packets.recv() channel
    /// and sends each packet on to the Packet.dest
    fn run_receive_packet(
        &self,
        socket: Arc<UdpSocket>,
        mut receive_packets: mpsc::Receiver<UpstreamPacket>,
    ) {
        tokio::spawn(async move {
            while let Some(packet) = receive_packets.recv().await {
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

                if let Err(error) = socket.send_to(packet.contents(), address).await {
                    tracing::error!(dest = %packet.dest(), %error, "Error sending packet");
                }
                packet.stop_and_record();
            }
            tracing::debug!("Receiver closed");
            Ok::<_, eyre::Error>(())
        });
    }

    /// binds the local configured port with port and address reuse applied.
    async fn bind(&self) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.config.proxy.port);
        net::socket_with_reuse(addr.into())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use prometheus::{Histogram, HistogramOpts};
    use tokio::{
        sync::mpsc,
        time::{timeout, Duration},
    };

    use crate::{
        cluster::SharedCluster,
        config,
        endpoint::Endpoint,
        filters::SharedFilterChain,
        proxy::{
            server::metrics::Metrics as ProxyMetrics, sessions::metrics::Metrics as SessionMetrics,
            sessions::UpstreamPacket,
        },
        test_utils::{config_with_dummy_endpoint, get_local_addr, load_test_filters, TestHelper},
    };

    use super::*;

    #[tokio::test]
    async fn run_server() {
        let mut t = TestHelper::default();

        let endpoint1 = t.open_socket_and_recv_single_packet().await;
        let mut endpoint2 = t.open_socket_and_recv_single_packet().await;

        let local_addr = get_local_addr();
        let config = Server::builder()
            .port(local_addr.port())
            .endpoints(vec![
                Endpoint::new(endpoint1.socket.local_addr().unwrap().into()),
                Endpoint::new(endpoint2.socket.local_addr().unwrap().into()),
            ])
            .build()
            .unwrap();
        t.run_server_with_config(config);

        let msg = "hello";
        tryhard::retry_fn(|| {
            let mut rx = endpoint1.packet_rx.clone();

            async move {
                // Use a standard socket in test utils as we only want to bind sockets to unused ports.
                let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
                tracing::debug!(dest = %local_addr, source = %socket.local_addr().unwrap(), "Sending Packet");
                socket.send_to(msg.as_bytes(), &local_addr).await.unwrap();
                timeout(Duration::from_millis(100), rx.changed()).await
            }
        }).retries(10)
        .fixed_backoff(Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();

        assert_eq!(msg, *endpoint1.packet_rx.borrow());
        timeout(Duration::from_secs(1), endpoint2.packet_rx.changed())
            .await
            .expect("should get a packet")
            .unwrap();
        assert_eq!(msg, *endpoint2.packet_rx.borrow());
    }

    #[tokio::test]
    async fn run_client() {
        // pretty_print();
        let mut t = TestHelper::default();

        let endpoint = t.open_socket_and_recv_single_packet().await;

        let local_addr = get_local_addr();
        let config = Server::builder()
            .port(local_addr.port())
            .endpoints(vec![Endpoint::new(
                endpoint.socket.local_addr().unwrap().into(),
            )])
            .build()
            .unwrap();
        t.run_server_with_config(config);

        let msg = "hello";
        let mut i = 0;
        tryhard::retry_fn(|| {
            let mut rx = endpoint.packet_rx.clone();
            if i > 0 {
                println!("--- RETRYING --- {i}");
            }
            i += i;

            async move {
                // Use a standard socket in test utils as we only want to bind sockets to unused ports.
                let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
                tracing::debug!(dest = %local_addr, source = %socket.local_addr().unwrap(), "Sending Packet");
                socket.send_to(msg.as_bytes(), &local_addr).await.unwrap();
                timeout(Duration::from_millis(100), rx.changed()).await
            }
        })
        .retries(10)
        .fixed_backoff(Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();

        assert_eq!(msg, *endpoint.packet_rx.borrow());
    }

    #[tokio::test]
    async fn run_with_filter() {
        let mut t = TestHelper::default();

        load_test_filters();
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = get_local_addr();
        let config = Server::builder()
            .port(local_addr.port())
            .filters(vec![config::Filter {
                name: "TestFilter".to_string(),
                config: None,
            }])
            .endpoints(vec![Endpoint::new(
                endpoint.socket.local_addr().unwrap().into(),
            )])
            .build()
            .unwrap();
        t.run_server_with_config(config);

        let msg = "hello";

        tryhard::retry_fn(|| {
            let mut rx = endpoint.packet_rx.clone();

            async move {
                // Use a standard socket in test utils as we only want to bind sockets to unused ports.
                let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.unwrap();
                socket.send_to(msg.as_bytes(), &local_addr).await.unwrap();
                timeout(Duration::from_millis(100), rx.changed()).await
            }
        })
        .retries(10)
        .fixed_backoff(Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();

        // search for the filter strings.
        let result = &*endpoint.packet_rx.borrow();
        assert!(result.contains(msg), "'{}' not found in '{}'", msg, result);
        assert!(result.contains(":odr:"), ":odr: not found in '{}'", result);
    }

    #[tokio::test]
    async fn spawn_downstream_receive_workers() {
        let t = TestHelper::default();

        let socket = t.create_socket().await;
        let addr = socket.local_addr().unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let mut endpoint = t.open_socket_and_recv_single_packet().await;
        let (send_packets, _) = mpsc::channel::<UpstreamPacket>(1);
        let msg = "hello";

        // we'll test a single DownstreamReceiveWorkerConfig
        let config = DownstreamReceiveWorkerConfig {
            worker_id: 1,
            socket,
            receive_config: ProcessDownstreamReceiveConfig {
                proxy_metrics: ProxyMetrics::new().unwrap(),
                session_metrics: SessionMetrics::new().unwrap(),
                cluster: SharedCluster::new_static_cluster(vec![Endpoint::new(
                    endpoint.socket.local_addr().unwrap().into(),
                )])
                .unwrap(),
                filter_chain: SharedFilterChain::empty(),
                session_manager: SessionManager::new(shutdown_rx.clone()),
                session_ttl: Duration::from_secs(10),
                send_packets,
            },
            shutdown_rx,
        };

        Server::spawn_downstream_receive_workers(vec![config]);

        let socket = t.create_socket().await;
        socket.send_to(msg.as_bytes(), &addr).await.unwrap();
        timeout(Duration::from_secs(1), endpoint.packet_rx.changed())
            .await
            .expect("should receive a packet")
            .unwrap();
        assert_eq!(msg, *endpoint.packet_rx.borrow());
    }

    #[tokio::test]
    async fn run_recv_from() {
        let t = TestHelper::default();
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        let msg = "hello";
        let mut endpoint = t.open_socket_and_recv_single_packet().await;
        let session_manager = SessionManager::new(shutdown_rx.clone());
        let (send_packets, mut recv_packets) = mpsc::channel::<UpstreamPacket>(1);
        let local_addr = get_local_addr();
        let mut config = config_with_dummy_endpoint().build().unwrap();
        config.proxy.port = local_addr.port();

        let server = Server::try_from(config).unwrap();

        server
            .run_recv_from(RunRecvFromArgs {
                cluster: SharedCluster::new_static_cluster(vec![Endpoint::new(
                    endpoint.socket.local_addr().unwrap().into(),
                )])
                .unwrap(),
                filter_chain: SharedFilterChain::empty(),
                session_manager: session_manager.clone(),
                session_ttl: Duration::from_secs(10),
                send_packets,
                shutdown_rx,
            })
            .await
            .unwrap();

        let socket = t.create_socket().await;
        socket.send_to(msg.as_bytes(), &local_addr).await.unwrap();

        timeout(Duration::from_secs(1), endpoint.packet_rx.changed())
            .await
            .expect("should receive a packet")
            .unwrap();
        assert_eq!(msg, *endpoint.packet_rx.borrow());
        recv_packets.close();
    }

    #[tokio::test]
    async fn run_receive_packet() {
        let t = TestHelper::default();

        let histogram = Histogram::with_opts(HistogramOpts::new("test", "test")).unwrap();

        let msg = "hello";

        // without a filter
        let (send_packet, recv_packet) = mpsc::channel::<UpstreamPacket>(1);
        let mut endpoint = t.open_socket_and_recv_single_packet().await;
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
        let config = config_with_dummy_endpoint().build().unwrap();
        let server = Server::try_from(config).unwrap();
        server.run_receive_packet(endpoint.socket, recv_packet);
        timeout(Duration::from_secs(1), endpoint.packet_rx.changed())
            .await
            .expect("should receive a packet")
            .unwrap();
        assert_eq!(msg, *endpoint.packet_rx.borrow());
        assert_eq!(
            1_u64,
            histogram.get_sample_count(),
            "one packet sent, so there should be one sample"
        );
    }
}
