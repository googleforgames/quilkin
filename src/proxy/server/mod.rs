/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::result::Result as StdResult;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use slog::{debug, error, info, trace, warn, Logger};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};

use metrics::Metrics as ProxyMetrics;
use resource_manager::{DynamicResourceManagers, StaticResourceManagers};

use crate::cluster::cluster_manager::SharedClusterManager;
use crate::cluster::Endpoint;
use crate::extensions::filter_manager::SharedFilterManager;
use crate::extensions::{Filter, FilterRegistry, ReadContext};
use crate::proxy::builder::{ValidatedConfig, ValidatedSource};
use crate::proxy::server::error::Error;
use crate::proxy::sessions::{
    Packet, Session, SESSION_EXPIRY_POLL_INTERVAL, SESSION_TIMEOUT_SECONDS,
};
use crate::utils::debug;

use super::metrics::Metrics;
use crate::proxy::Admin;

pub mod error;
pub(super) mod metrics;
mod resource_manager;

type SessionMap = Arc<RwLock<HashMap<(SocketAddr, SocketAddr), Session>>>;

type Result<T> = std::result::Result<T, Error>;

/// Server is the UDP server main implementation
pub struct Server {
    // We use pub(super) to limit instantiation only to the Builder.
    pub(super) log: Logger,
    pub(super) config: Arc<ValidatedConfig>,
    // Admin may be turned off, primarily for testing.
    pub(super) admin: Option<Admin>,
    pub(super) metrics: Arc<Metrics>,
    pub(super) proxy_metrics: ProxyMetrics,
    pub(super) filter_registry: Arc<FilterRegistry>,
}

/// Represents arguments to the `Server::run_recv_from` method.
struct RunRecvFromArgs {
    cluster_manager: SharedClusterManager,
    filter_manager: SharedFilterManager,
    socket: Arc<UdpSocket>,
    sessions: SessionMap,
    session_ttl: Duration,
    send_packets: mpsc::Sender<Packet>,
    shutdown_rx: watch::Receiver<()>,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
struct DownstreamReceiveWorkerConfig {
    /// ID of the worker.
    worker_id: usize,
    /// Channel from which the worker picks up the downstream packets.
    packet_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    /// Configuration required to process a received downstream packet.
    receive_config: ProcessDownstreamReceiveConfig,
    /// The worker task exits when a value is received from this shutdown channel.
    shutdown_rx: watch::Receiver<()>,
}

/// Contains arguments to process a received downstream packet, through the
/// filter chain and session pipeline.
struct ProcessDownstreamReceiveConfig {
    log: Logger,
    metrics: Arc<Metrics>,
    proxy_metrics: ProxyMetrics,
    cluster_manager: SharedClusterManager,
    filter_manager: SharedFilterManager,
    sessions: SessionMap,
    session_ttl: Duration,
    send_packets: mpsc::Sender<Packet>,
}

impl Server {
    /// start the async processing of incoming UDP packets. Will block until an
    /// event is sent through the stop Receiver.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
        self.log_config();

        if let Some(admin) = &self.admin {
            admin.run(shutdown_rx.clone());
        }

        let socket = Arc::new(Server::bind(self.config.proxy.port).await?);
        // HashMap key is from,destination addresses as a tuple.
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let (send_packets, receive_packets) = mpsc::channel::<Packet>(1024);

        let session_ttl = Duration::from_secs(SESSION_TIMEOUT_SECONDS);
        let poll_interval = Duration::from_secs(SESSION_EXPIRY_POLL_INTERVAL);

        let (cluster_manager, filter_manager) =
            self.create_resource_managers(shutdown_rx.clone()).await?;
        self.run_receive_packet(socket.clone(), receive_packets);
        self.run_prune_sessions(&sessions, poll_interval);
        let recv_loop = self.run_recv_from(RunRecvFromArgs {
            cluster_manager,
            filter_manager,
            socket,
            sessions: sessions.clone(),
            session_ttl,
            send_packets,
            shutdown_rx: shutdown_rx.clone(),
        });

        tokio::select! {
            join_result = recv_loop => {
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

    /// run_prune_sessions starts the timer for pruning sessions and runs prune_sessions every
    /// SESSION_TIMEOUT_SECONDS, via a tokio::spawn, i.e. it's non-blocking.
    /// Pruning will occur ~ every interval period. So the timeout expiration may sometimes
    /// exceed the expected, but we don't have to write lock the SessionMap as often to clean up.
    fn run_prune_sessions(&self, sessions: &SessionMap, poll_interval: Duration) {
        let log = self.log.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            // TODO: Add a shutdown channel to this task.
            loop {
                sleep(poll_interval).await;
                debug!(log, "Attempting to Prune Sessions");
                Server::prune_sessions(&log, sessions.clone()).await;
            }
        });
    }

    /// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
    /// Each received packet is placed on a queue to be processed by a worker task.
    /// This function also spawns the set of worker tasks responsible for consuming packets
    /// off the aforementioned queue and processing them through the filter chain and session
    /// pipeline.
    fn run_recv_from(&self, args: RunRecvFromArgs) -> JoinHandle<StdResult<(), String>> {
        let sessions = args.sessions;
        let log = self.log.clone();
        let metrics = self.metrics.clone();
        let proxy_metrics = self.proxy_metrics.clone();

        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = num_cpus::get();

        // Contains channel Senders for each worker task.
        let mut packet_txs = vec![];
        // Contains config for each worker task.
        let mut worker_configs = vec![];
        for worker_id in 0..num_workers {
            let (packet_tx, packet_rx) = mpsc::channel(num_workers);
            packet_txs.push(packet_tx);
            worker_configs.push(DownstreamReceiveWorkerConfig {
                worker_id,
                packet_rx,
                shutdown_rx: args.shutdown_rx.clone(),
                receive_config: ProcessDownstreamReceiveConfig {
                    log: log.clone(),
                    metrics: metrics.clone(),
                    proxy_metrics: proxy_metrics.clone(),
                    cluster_manager: args.cluster_manager.clone(),
                    filter_manager: args.filter_manager.clone(),
                    sessions: sessions.clone(),
                    session_ttl: args.session_ttl,
                    send_packets: args.send_packets.clone(),
                },
            })
        }

        // Start the worker tasks that pick up received packets from their queue
        // and processes them.
        Self::spawn_downstream_receive_workers(log.clone(), worker_configs);

        // Start the background task to receive downstream packets from the socket
        // and place them onto the worker tasks' queue for processing.
        let socket = args.socket;
        tokio::spawn(async move {
            // Index to round-robin over workers to process packets.
            let mut next_worker = 0;
            let num_workers = num_workers;

            // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
            // packet, which is the maximum value of 16 a bit integer.
            let mut buf = [0; 1 << 16];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, recv_addr)) => {
                        let packet_tx = &mut packet_txs[next_worker % num_workers];
                        next_worker += 1;

                        if packet_tx
                            .send((recv_addr, (&buf[..size]).to_vec()))
                            .await
                            .is_err()
                        {
                            // We cannot recover from this error since
                            // it implies that the receiver has been dropped.
                            let reason =
                                "Failed to send received packet over channel to worker".into();
                            error!(log, "{}", reason);
                            return Err(reason);
                        }
                    }
                    err => {
                        // Socket error, we cannot recover from this so return an error instead.
                        error!(log, "Error processing receive socket"; "error" => #?err);
                        return Err(format!("error processing receive socket: {:?}", err));
                    }
                }
            }
        })
    }

    // For each worker config provided, spawn a background task that sits in a
    // loop, receiving packets from a queue and processing them through
    // the filter chain.
    fn spawn_downstream_receive_workers(
        log: Logger,
        worker_configs: Vec<DownstreamReceiveWorkerConfig>,
    ) {
        for DownstreamReceiveWorkerConfig {
            worker_id,
            mut packet_rx,
            mut shutdown_rx,
            receive_config,
        } in worker_configs
        {
            let log = log.clone();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                      packet = packet_rx.recv() => {
                        match packet {
                          Some((recv_addr, packet)) => Self::process_downstream_received_packet((recv_addr, packet), &receive_config).await,
                          None => {
                            debug!(log, "Worker-{} exiting: work sender channel was closed.", worker_id);
                            return;
                          }
                        }
                      }
                      _ = shutdown_rx.changed() => {
                        debug!(log, "Worker-{} exiting: received shutdown signal.", worker_id);
                        return;
                      }
                    }
                }
            });
        }
    }

    /// Processes a packet by running it through the filter chain.
    async fn process_downstream_received_packet(
        packet: (SocketAddr, Vec<u8>),
        args: &ProcessDownstreamReceiveConfig,
    ) {
        let (recv_addr, packet) = packet;

        trace!(
            args.log,
            "Packet Received";
            "from" => recv_addr,
            "contents" => debug::bytes_to_string(packet.to_vec()),
        );

        let endpoints = match args.cluster_manager.read().get_all_endpoints() {
            Some(endpoints) => endpoints,
            None => {
                args.proxy_metrics.packets_dropped_no_endpoints.inc();
                return;
            }
        };

        let filter_chain = {
            let filter_manager_guard = args.filter_manager.read();
            filter_manager_guard.get_filter_chain()
        };
        let result = filter_chain.read(ReadContext::new(endpoints, recv_addr, packet.to_vec()));

        if let Some(response) = result {
            for endpoint in response.endpoints.iter() {
                Self::session_send_packet(
                    &response.contents.as_slice(),
                    recv_addr,
                    endpoint,
                    &args,
                )
                .await;
            }
        }
    }

    /// Send a packet received from `recv_addr` to an endpoint.
    async fn session_send_packet(
        packet: &[u8],
        recv_addr: SocketAddr,
        endpoint: &Endpoint,
        args: &ProcessDownstreamReceiveConfig,
    ) {
        let session_key = (recv_addr, endpoint.address);

        // Grab a read lock and find the session.
        let guard = args.sessions.read().await;
        if let Some(session) = guard.get(&session_key) {
            // If it exists then send the packet, we're done.
            Self::session_send_packet_helper(&args.log, session, packet, args.session_ttl).await
        } else {
            // If it does not exist, grab a write lock so that we can create it.
            //
            // NOTE: We must drop the lock guard to release the lock before
            // trying to acquire a write lock since these lock aren't reentrant,
            // otherwise we will deadlock with our self.
            drop(guard);

            // Grab a write lock.
            let mut guard = args.sessions.write().await;

            // Although we have the write lock now, check whether some other thread
            // managed to create the session in-between our dropping the read
            // lock and grabbing the write lock.
            if let Some(session) = guard.get(&session_key) {
                // If the session now exists then we have less work to do,
                // simply send the packet.
                Self::session_send_packet_helper(&args.log, session, packet, args.session_ttl)
                    .await;
            } else {
                // Otherwise, create the session and insert into the map.
                match args
                    .metrics
                    .new_session_metrics(&session_key.0, &session_key.1)
                {
                    Ok(metrics) => {
                        match Session::new(
                            &args.log,
                            metrics,
                            args.filter_manager.clone(),
                            session_key.0,
                            endpoint.clone(),
                            args.send_packets.clone(),
                            args.session_ttl,
                        )
                        .await
                        {
                            Ok(session) => {
                                // Insert the session into the map and release the write lock
                                // immediately since we don't want to block other threads while we send
                                // the packet. Instead, re-acquire a read lock and send the packet.
                                guard.insert(session.key(), session);

                                // Release the write lock.
                                drop(guard);

                                // Grab a read lock to send the packet.
                                let guard = args.sessions.read().await;
                                if let Some(session) = guard.get(&session_key) {
                                    Self::session_send_packet_helper(
                                        &args.log,
                                        &session,
                                        packet,
                                        args.session_ttl,
                                    )
                                    .await;
                                } else {
                                    warn!(
                                        args.log,
                                        "Could not find session";
                                        "key" => format!("({}:{})", session_key.0.to_string(), session_key.1.to_string())
                                    )
                                }
                            }
                            Err(err) => {
                                error!(args.log, "Failed to ensure session exists"; "error" => %err);
                            }
                        }
                    }
                    Err(err) => {
                        error!(args.log, "Failed to create session metrics"; "error" => %err);
                    }
                }
            }
        }
    }

    // A helper function to push a session's packet on its socket.
    async fn session_send_packet_helper(
        log: &Logger,
        session: &Session,
        packet: &[u8],
        ttl: Duration,
    ) {
        match session.send(packet).await {
            Ok(_) => {
                if let Err(err) = session.update_expiration(ttl) {
                    warn!(log, "Error updating session expiration"; "error" => %err)
                }
            }
            Err(err) => error!(log, "Error sending packet from session"; "error" => %err),
        };
    }

    /// run_receive_packet is a non-blocking loop on receive_packets.recv() channel
    /// and sends each packet on to the Packet.dest
    fn run_receive_packet(
        &self,
        socket: Arc<UdpSocket>,
        mut receive_packets: mpsc::Receiver<Packet>,
    ) {
        let log = self.log.clone();
        tokio::spawn(async move {
            while let Some(packet) = receive_packets.recv().await {
                debug!(
                    log,
                    "Sending packet back to origin";
                    "origin" => packet.dest(),
                    "contents" => debug::bytes_to_string(packet.contents().clone()),
                );

                if let Err(err) = socket
                    .send_to(packet.contents().as_slice(), &packet.dest())
                    .await
                {
                    error!(log, "Error sending packet"; "dest" => %packet.dest(), "error" => %err);
                }
            }
            debug!(log, "Receiver closed");
        });
    }

    /// log_config outputs a log of what is configured
    fn log_config(&self) {
        info!(self.log, "Starting"; "port" => self.config.proxy.port);
    }

    /// bind binds the local configured port
    async fn bind(port: u16) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port);
        UdpSocket::bind(addr).await.map_err(Error::Bind)
    }

    /// prune_sessions removes expired Sessions from the SessionMap.
    /// Should be run on a time interval.
    /// This will lock the SessionMap if it finds expired sessions
    async fn prune_sessions(log: &Logger, sessions: SessionMap) {
        let now = if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            now.as_secs()
        } else {
            warn!(log, "Failed to get current time when pruning sessions");
            return;
        };

        let mut expired_keys = Vec::<(SocketAddr, SocketAddr)>::new();
        {
            let map = sessions.read().await;
            for (key, session) in map.iter() {
                let expiration = session.expiration();
                if expiration <= now {
                    expired_keys.push(*key);
                }
            }
        }

        if !expired_keys.is_empty() {
            let mut map = sessions.write().await;
            for key in expired_keys.iter() {
                if let Some(session) = map.get(key) {
                    // If the session has been updated since we marked it
                    // for removal then its still valid so ignore it.
                    if session.expiration() > now {
                        continue;
                    }

                    if let Err(err) = session.close() {
                        error!(log, "Error closing Session"; "error" => %err)
                    }
                }
                map.remove(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::ops::Add;
    use std::sync::Arc;

    use prometheus::Registry;
    use slog::info;
    use tokio::sync::{mpsc, RwLock};
    use tokio::time;
    use tokio::time::timeout;
    use tokio::time::Duration;

    use crate::cluster::cluster_manager::ClusterManager;
    use crate::config;
    use crate::config::{Builder as ConfigBuilder, EndPoint, Endpoints};
    use crate::extensions::filter_manager::FilterManager;
    use crate::extensions::{FilterChain, FilterRegistry};
    use crate::proxy::sessions::Packet;
    use crate::proxy::Builder;
    use crate::test_utils::{
        config_with_dummy_endpoint, TestFilter, TestFilterFactory, TestHelper,
    };

    use super::*;

    #[tokio::test]
    async fn run_server() {
        let mut t = TestHelper::default();

        let endpoint1 = t.open_socket_and_recv_single_packet().await;
        let endpoint2 = t.open_socket_and_recv_single_packet().await;

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12358);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(
                vec![],
                vec![
                    EndPoint::new(endpoint1.socket.local_addr().unwrap()),
                    EndPoint::new(endpoint2.socket.local_addr().unwrap()),
                ],
            )
            .build();
        t.run_server(Builder::from(Arc::new(config)).disable_admin());

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
                vec![EndPoint::new(endpoint.socket.local_addr().unwrap())],
            )
            .build();
        t.run_server(Builder::from(Arc::new(config)).disable_admin());

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

        let mut registry = FilterRegistry::default();
        registry.insert(TestFilterFactory {});

        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12367);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(
                vec![config::Filter {
                    name: "TestFilter".to_string(),
                    config: None,
                }],
                vec![EndPoint::new(endpoint.socket.local_addr().unwrap())],
            )
            .build();
        t.run_server(
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
        assert!(
            result.contains(msg),
            format!("'{}' not found in '{}'", msg, result)
        );
        assert!(
            result.contains(":odr:"),
            format!(":odr: not found in '{}'", result)
        );
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
            shutdown_rx: watch::Receiver<()>,
        ) -> Result {
            let t = TestHelper::default();

            info!(t.log, "Test"; "name" => name);
            let msg = "hello".to_string();
            let endpoint = t.open_socket_and_recv_single_packet().await;

            let socket = t.create_socket().await;
            let mut receive_addr = socket.local_addr().unwrap();
            // need to switch to 127.0.0.1, as the request comes locally
            receive_addr.set_ip("127.0.0.1".parse().unwrap());

            let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
            let (send_packets, mut recv_packets) = mpsc::channel::<Packet>(1);

            let time_increment = 10;
            time::advance(Duration::from_secs(time_increment)).await;

            let endpoint_address = endpoint.socket.local_addr().unwrap();

            let num_workers = 2;
            let mut packet_txs = Vec::with_capacity(num_workers);
            let mut worker_configs = Vec::with_capacity(num_workers);

            let cluster_manager = ClusterManager::fixed(
                &Registry::default(),
                Endpoints::new(vec![Endpoint::from_address(endpoint_address)]).unwrap(),
            )
            .unwrap();
            let filter_manager = FilterManager::fixed(chain.clone());
            for worker_id in 0..num_workers {
                let (packet_tx, packet_rx) = mpsc::channel(num_workers);
                packet_txs.push(packet_tx);

                let metrics = Arc::new(Metrics::new(&t.log, Registry::default()));
                let proxy_metrics = ProxyMetrics::new(&metrics.registry).unwrap();
                worker_configs.push(DownstreamReceiveWorkerConfig {
                    worker_id,
                    packet_rx,
                    shutdown_rx: shutdown_rx.clone(),
                    receive_config: ProcessDownstreamReceiveConfig {
                        log: t.log.clone(),
                        metrics,
                        proxy_metrics,
                        cluster_manager: cluster_manager.clone(),
                        filter_manager: filter_manager.clone(),
                        sessions: sessions.clone(),
                        session_ttl: Duration::from_secs(10),
                        send_packets: send_packets.clone(),
                    },
                })
            }

            Server::spawn_downstream_receive_workers(t.log.clone(), worker_configs);

            for packet_tx in packet_txs {
                packet_tx
                    .send((receive_addr, msg.as_bytes().to_vec()))
                    .await
                    .unwrap();
            }

            socket.send_to(msg.as_bytes(), &receive_addr).await.unwrap();

            let result = endpoint.packet_rx.await.unwrap();
            recv_packets.close();

            let map = sessions.read().await;
            assert_eq!(expected.session_len, map.len());
            let build_key = (receive_addr, endpoint.socket.local_addr().unwrap());
            assert!(map.contains_key(&build_key));
            let session = map.get(&build_key).unwrap();
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let diff = session.expiration() - now_secs;
            assert!(diff >= 5 && diff <= 10);

            Result {
                msg: result,
                addr: receive_addr,
            }
        }

        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let chain = Arc::new(FilterChain::new(vec![]));
        let result = test(
            "no filter".to_string(),
            chain,
            Expected { session_len: 1 },
            shutdown_rx.clone(),
        )
        .await;
        assert_eq!("hello", result.msg);

        let chain = Arc::new(FilterChain::new(vec![Box::new(TestFilter {})]));
        let result = test(
            "test filter".to_string(),
            chain,
            Expected { session_len: 1 },
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

        let msg = "hello";
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let socket = t.create_socket().await;
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let (send_packets, mut recv_packets) = mpsc::channel::<Packet>(1);

        let config = Arc::new(config_with_dummy_endpoint().build());
        let server = Builder::from(config).validate().unwrap().build();

        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        server.run_recv_from(RunRecvFromArgs {
            cluster_manager: ClusterManager::fixed(
                &Registry::default(),
                Endpoints::new(vec![Endpoint::from_address(
                    endpoint.socket.local_addr().unwrap(),
                )])
                .unwrap(),
            )
            .unwrap(),
            filter_manager: FilterManager::fixed(Arc::new(FilterChain::new(vec![]))),
            socket: socket.clone(),
            sessions: sessions.clone(),
            session_ttl: Duration::from_secs(10),
            send_packets,
            shutdown_rx,
        });

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

        let msg = "hello";

        // without a filter
        let (send_packet, recv_packet) = mpsc::channel::<Packet>(1);
        let endpoint = t.open_socket_and_recv_single_packet().await;
        if send_packet
            .send(Packet::new(
                endpoint.socket.local_addr().unwrap(),
                msg.as_bytes().to_vec(),
            ))
            .await
            .is_err()
        {
            unreachable!("failed to send packet over channel");
        }
        let config = Arc::new(config_with_dummy_endpoint().build());
        let server = Builder::from(config).validate().unwrap().build();
        server.run_receive_packet(endpoint.socket, recv_packet);
        assert_eq!(msg, endpoint.packet_rx.await.unwrap());
    }

    #[tokio::test]
    async fn prune_sessions() {
        let t = TestHelper::default();
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let to: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (send, _recv) = mpsc::channel::<Packet>(1);
        let endpoint = Endpoint::from_address(to);

        let key = (from, to);
        let ttl = Duration::from_secs(1);

        {
            let mut sessions = sessions.write().await;
            sessions.insert(
                key,
                Session::new(
                    &t.log,
                    Metrics::new(&t.log, Registry::default())
                        .new_session_metrics(&from, &endpoint.address)
                        .unwrap(),
                    FilterManager::fixed(Arc::new(FilterChain::new(vec![]))),
                    from,
                    endpoint.clone(),
                    send,
                    ttl,
                )
                .await
                .unwrap(),
            );
        }

        // Insert key.
        {
            let map = sessions.read().await;
            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // session map should be the same since, we haven't passed expiry
        Server::prune_sessions(&t.log, sessions.clone()).await;
        {
            let map = sessions.read().await;
            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // Wait until the key has expired.
        time::sleep_until(time::Instant::now().add(ttl)).await;

        Server::prune_sessions(&t.log, sessions.clone()).await;
        {
            let map = sessions.read().await;
            assert!(
                !map.contains_key(&key),
                "should not contain the key after prune"
            );
            assert_eq!(0, map.len(), "len should be 0, bit is {}", map.len());
        }
        info!(t.log, "test complete");
    }

    #[tokio::test]
    async fn run_prune_sessions() {
        let t = TestHelper::default();
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let to: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (send, _recv) = mpsc::channel::<Packet>(1);

        let endpoint = Endpoint::from_address(to);

        let ttl = Duration::from_secs(1);
        let poll_interval = Duration::from_millis(1);

        let config = Arc::new(config_with_dummy_endpoint().build());
        let server = Builder::from(config).validate().unwrap().build();
        server.run_prune_sessions(&sessions, poll_interval);

        let key = (from, to);

        // Insert key.
        {
            let mut sessions = sessions.write().await;
            sessions.insert(
                key,
                Session::new(
                    &t.log,
                    Metrics::new(&t.log, Registry::default())
                        .new_session_metrics(&from, &endpoint.address)
                        .unwrap(),
                    FilterManager::fixed(Arc::new(FilterChain::new(vec![]))),
                    from,
                    endpoint.clone(),
                    send,
                    ttl,
                )
                .await
                .unwrap(),
            );
        }

        // session map should be the same since, we haven't passed expiry
        {
            let map = sessions.read().await;

            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // Wait until the key has expired.
        time::sleep_until(time::Instant::now().add(ttl)).await;

        // poll, since cleanup is async, and may not have happened yet
        for _ in 1..10000 {
            time::sleep(Duration::from_millis(1)).await;
            let map = sessions.read().await;
            if !map.contains_key(&key) && map.len() == 0 {
                break;
            }
        }
        // do final assertion
        {
            let map = sessions.read().await;
            assert!(
                !map.contains_key(&key),
                "should not contain the key after prune"
            );
            assert_eq!(0, map.len(), "len should be 0, bit is {}", map.len());
        }
    }
}
