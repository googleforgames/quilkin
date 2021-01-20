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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_intrusive::sync::{GenericSharedSemaphore, GenericSharedSemaphoreReleaser};
use parking_lot::RawMutex;
use slog::{debug, error, info, trace, warn, Logger};
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, watch};
use tokio::time::{delay_for, Duration};

use metrics::Metrics as ProxyMetrics;

use crate::cluster::cluster_manager::{ClusterManager, SharedClusterManager};
use crate::config::{Config, Source};
use crate::extensions::{DownstreamContext, Filter, FilterChain};
use crate::proxy::server::error::{Error, RecvFromError};
use crate::proxy::sessions::{
    Packet, Session, SESSION_EXPIRY_POLL_INTERVAL, SESSION_TIMEOUT_SECONDS,
};
use crate::utils::debug;

use super::metrics::{start_metrics_server, Metrics};
use crate::cluster::Endpoint;

pub mod error;
pub(super) mod metrics;

type SessionMap = Arc<RwLock<HashMap<(SocketAddr, SocketAddr), Session>>>;

type Result<T> = std::result::Result<T, Error>;

/// Server is the UDP server main implementation
pub struct Server {
    // We use pub(super) to limit instantiation only to the Builder.
    pub(super) log: Logger,
    pub(super) config: Arc<Config>,
    pub(super) filter_chain: Arc<FilterChain>,
    pub(super) metrics: Metrics,
    pub(super) proxy_metrics: ProxyMetrics,
}

struct RecvFromArgs {
    log: Logger,
    metrics: Metrics,
    proxy_metrics: ProxyMetrics,
    cluster_manager: SharedClusterManager,
    chain: Arc<FilterChain>,
    sessions: SessionMap,
    session_ttl: Duration,
    send_packets: mpsc::Sender<Packet>,
}

impl Server {
    /// start the async processing of incoming UDP packets. Will block until an
    /// event is sent through the stop Receiver.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
        self.log_config();

        if let Some(addr) = self.metrics.addr {
            start_metrics_server(
                addr,
                self.metrics.registry.clone(),
                shutdown_rx.clone(),
                self.log.clone(),
            );
        }

        let (receive_socket, send_socket) = Server::bind(&self.config).await?.split();
        // HashMap key is from,destination addresses as a tuple.
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let (send_packets, receive_packets) = mpsc::channel::<Packet>(1024);

        let session_ttl = Duration::from_secs(SESSION_TIMEOUT_SECONDS);
        let poll_interval = Duration::from_secs(SESSION_EXPIRY_POLL_INTERVAL);

        self.run_receive_packet(send_socket, receive_packets);
        self.run_prune_sessions(&sessions, poll_interval);
        self.run_recv_from(
            self.create_cluster_manager(shutdown_rx.clone()).await?,
            self.filter_chain.clone(),
            receive_socket,
            &sessions,
            session_ttl,
            send_packets,
        );

        let _ = shutdown_rx.recv().await;
        Ok(())
    }

    async fn create_cluster_manager(
        &self,
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<SharedClusterManager> {
        match &self.config.source {
            Source::Static {
                filters: _,
                endpoints: config_endpoints,
            } => {
                let mut endpoints = Vec::with_capacity(config_endpoints.len());
                for ep in config_endpoints {
                    // TODO: We should a validated config type so that we don't need to
                    //  handle errors when using its values later on since we know it's validated.
                    endpoints
                        .push(Endpoint::from_config(ep).map_err(Error::InvalidEndpointConfig)?);
                }
                Ok(ClusterManager::fixed(endpoints))
            }
            Source::Dynamic {
                filters: _,
                management_servers,
            } => {
                let (cm, execution_result_rx) = ClusterManager::from_xds(
                    self.log.clone(),
                    management_servers.to_vec(),
                    self.config.proxy.id.clone(),
                    shutdown_rx,
                )
                .await
                .map_err(|err| Error::Initialize(format!("{}", err)))?;

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

                Ok(cm)
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
                delay_for(poll_interval).await;
                debug!(log, "Attempting to Prune Sessions");
                Server::prune_sessions(&log, sessions.clone()).await;
            }
        });
    }

    // run_recv_from is a non blocking function that continually runs
    // Server::recv_from() to process new incoming packets.
    fn run_recv_from(
        &self,
        cluster_manager: SharedClusterManager,
        chain: Arc<FilterChain>,
        mut receive_socket: RecvHalf,
        sessions: &SessionMap,
        session_ttl: Duration,
        send_packets: mpsc::Sender<Packet>,
    ) {
        let sessions = sessions.clone();
        let log = self.log.clone();
        let metrics = self.metrics.clone();
        let proxy_metrics = self.proxy_metrics.clone();

        // Limits the maximum number of tasks that are processing packets
        // at any given time.
        // We don't want to set to this a large number since otherwise the tasks
        // would likely spend too much time contending for locks. (Also it seems to
        // trigger a weird Tokio bug where spawning a large number of tasks
        // (e.g 1024) allocates a large amount of memory that is never reclaimed).
        // The current value is set based on local tests.
        let max_concurrent_packets = 16;
        let semaphore: GenericSharedSemaphore<RawMutex> =
            GenericSharedSemaphore::new(false, max_concurrent_packets);

        tokio::spawn(async move {
            loop {
                let permit = semaphore.acquire(1).await;
                if let Err(err) = Server::recv_from(
                    &mut receive_socket,
                    permit,
                    RecvFromArgs {
                        log: log.clone(),
                        metrics: metrics.clone(),
                        proxy_metrics: proxy_metrics.clone(),
                        cluster_manager: cluster_manager.clone(),
                        chain: chain.clone(),
                        sessions: sessions.clone(),
                        session_ttl,
                        send_packets: send_packets.clone(),
                    },
                )
                .await
                {
                    error!(log, "Error processing receive socket"; "err" => %err);
                }
            }
        });
    }

    /// recv_from takes packets from the local socket and asynchronously
    /// processes them to send them out to endpoints.
    async fn recv_from(
        receive_socket: &mut RecvHalf,
        permit: GenericSharedSemaphoreReleaser<RawMutex>,
        args: RecvFromArgs,
    ) -> std::result::Result<(), RecvFromError> {
        let mut buf: Vec<u8> = vec![0; 65535];
        let (size, recv_addr) = receive_socket
            .recv_from(&mut buf)
            .await
            .map_err(RecvFromError)?;

        tokio::spawn(async move {
            // Do not let the semaphore permit go out of scope until we're done.
            let _permit = permit;

            let packet = &buf[..size];

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

            let result = args.chain.on_downstream_receive(DownstreamContext::new(
                endpoints,
                recv_addr,
                packet.to_vec(),
            ));

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
        });
        Ok(())
    }

    /// Send a packet received from `recv_addr` to an endpoint.
    async fn session_send_packet(
        packet: &[u8],
        recv_addr: SocketAddr,
        endpoint: &Endpoint,
        args: &RecvFromArgs,
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
                            args.chain.clone(),
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
                                        "Could not find session for key: ({}:{})",
                                        session_key.0.to_string(),
                                        session_key.1.to_string()
                                    )
                                }
                            }
                            Err(err) => {
                                error!(args.log, "failed to ensure session exists"; "error" => %err);
                            }
                        }
                    }
                    Err(err) => {
                        error!(args.log, "failed to create session metrics"; "error" => %err);
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
        mut send_socket: SendHalf,
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

                if let Err(err) = send_socket
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
        info!(self.log, "Starting on port {}", self.config.proxy.port);
    }

    /// bind binds the local configured port
    async fn bind(config: &Config) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.proxy.port);
        UdpSocket::bind(addr).await.map_err(Error::Bind)
    }

    /// prune_sessions removes expired Sessions from the SessionMap.
    /// Should be run on a time interval.
    /// This will lock the SessionMap if it finds expired sessions
    async fn prune_sessions(log: &Logger, sessions: SessionMap) {
        let now = if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            now.as_secs()
        } else {
            warn!(log, "failed to get current time when pruning sessions");
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
    use std::sync::Arc;

    use futures_intrusive::sync::GenericSharedSemaphore;
    use parking_lot::RawMutex;
    use slog::info;
    use tokio::sync::{mpsc, RwLock};
    use tokio::time;
    use tokio::time::Duration;

    use crate::config;
    use crate::config::{Builder as ConfigBuilder, EndPoint};
    use crate::extensions::FilterRegistry;
    use crate::proxy::sessions::Packet;
    use crate::proxy::Builder;
    use crate::test_utils::{
        config_with_dummy_endpoint, SplitSocket, TestFilter, TestFilterFactory, TestHelper,
    };

    use super::*;
    use std::ops::Add;

    #[tokio::test]
    async fn run_server() {
        let mut t = TestHelper::default();

        let mut endpoint1 = t.open_socket_and_recv_single_packet().await;
        let endpoint2 = t.open_socket_and_recv_single_packet().await;

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12358);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(
                vec![],
                vec![EndPoint::new(endpoint1.addr), EndPoint::new(endpoint2.addr)],
            )
            .build();
        t.run_server(config);

        let msg = "hello";
        endpoint1
            .send
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(msg, endpoint1.packet_rx.await.unwrap());
        assert_eq!(msg, endpoint2.packet_rx.await.unwrap());
    }

    #[tokio::test]
    async fn run_client() {
        let mut t = TestHelper::default();

        let mut endpoint = t.open_socket_and_recv_single_packet().await;

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(vec![], vec![EndPoint::new(endpoint.addr)])
            .build();
        t.run_server(config);

        let msg = "hello";
        endpoint
            .send
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

        let mut endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12367);
        let config = ConfigBuilder::empty()
            .with_port(local_addr.port())
            .with_static(
                vec![config::Filter {
                    name: "TestFilter".to_string(),
                    config: None,
                }],
                vec![EndPoint::new(endpoint.addr)],
            )
            .build();
        t.run_server_with_filter_registry(config, registry);

        let msg = "hello";
        endpoint
            .send
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
        let config = config_with_dummy_endpoint().with_port(12345).build();
        let socket = Server::bind(&config).await.unwrap();
        let addr = socket.local_addr().unwrap();

        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12345);
        assert_eq!(expected, addr)
    }

    #[tokio::test]
    async fn recv_from() {
        time::pause();

        struct Result {
            msg: String,
            addr: SocketAddr,
        }
        struct Expected {
            session_len: usize,
        }

        async fn test(name: String, chain: Arc<FilterChain>, expected: Expected) -> Result {
            let t = TestHelper::default();

            info!(t.log, "Test"; "name" => name);
            let msg = "hello".to_string();
            let endpoint = t.open_socket_and_recv_single_packet().await;

            let SplitSocket {
                addr: receive_addr,
                mut recv,
                mut send,
            } = t.create_and_split_socket().await;

            let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
            let (send_packets, mut recv_packets) = mpsc::channel::<Packet>(1);

            let sessions_clone = sessions.clone();

            let time_increment = 10;
            time::advance(Duration::from_secs(time_increment)).await;

            let endpoint_address = endpoint.addr;
            let semaphore: GenericSharedSemaphore<RawMutex> =
                GenericSharedSemaphore::new(false, 10);
            tokio::spawn(async move {
                Server::recv_from(
                    &mut recv,
                    semaphore.acquire(1).await,
                    RecvFromArgs {
                        log: t.log.clone(),
                        metrics: Metrics::default(),
                        proxy_metrics: ProxyMetrics::new(&Metrics::default().registry).unwrap(),
                        cluster_manager: ClusterManager::fixed(vec![Endpoint::from_address(
                            endpoint_address,
                        )]),
                        chain,
                        sessions: sessions_clone,
                        send_packets: send_packets.clone(),
                        session_ttl: Duration::from_secs(10),
                    },
                )
                .await
            });

            send.send_to(msg.as_bytes(), &receive_addr).await.unwrap();

            let result = endpoint.packet_rx.await.unwrap();
            recv_packets.close();

            let map = sessions.read().await;
            assert_eq!(expected.session_len, map.len());

            // need to switch to 127.0.0.1, as the request comes locally
            let mut receive_addr_local = receive_addr;
            receive_addr_local.set_ip("127.0.0.1".parse().unwrap());
            let build_key = (receive_addr_local, endpoint.addr);
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
                addr: receive_addr_local,
            }
        }

        let chain = Arc::new(FilterChain::new(vec![]));
        let result = test("no filter".to_string(), chain, Expected { session_len: 1 }).await;
        assert_eq!("hello", result.msg);

        let chain = Arc::new(FilterChain::new(vec![Box::new(TestFilter {})]));
        let result = test(
            "test filter".to_string(),
            chain,
            Expected { session_len: 1 },
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
        let SplitSocket {
            addr,
            recv,
            mut send,
        } = t.create_and_split_socket().await;
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let (send_packets, mut recv_packets) = mpsc::channel::<Packet>(1);

        let config = Arc::new(config_with_dummy_endpoint().build());
        let server = Builder::from(config).validate().unwrap().build();

        server.run_recv_from(
            ClusterManager::fixed(vec![Endpoint::from_address(endpoint.addr)]),
            server.filter_chain.clone(),
            recv,
            &sessions,
            Duration::from_secs(10),
            send_packets,
        );

        send.send_to(msg.as_bytes(), &addr).await.unwrap();
        assert_eq!(msg, endpoint.packet_rx.await.unwrap());
        recv_packets.close();
    }

    #[tokio::test]
    async fn run_receive_packet() {
        let t = TestHelper::default();

        let msg = "hello";

        // without a filter
        let (mut send_packet, recv_packet) = mpsc::channel::<Packet>(5);
        let endpoint = t.open_socket_and_recv_single_packet().await;
        if send_packet
            .send(Packet::new(endpoint.addr, msg.as_bytes().to_vec()))
            .await
            .is_err()
        {
            unreachable!("failed to send packet over channel");
        }
        let config = Arc::new(config_with_dummy_endpoint().build());
        let server = Builder::from(config).validate().unwrap().build();
        server.run_receive_packet(endpoint.send, recv_packet);
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
                    Metrics::default()
                        .new_session_metrics(&from, &endpoint.address)
                        .unwrap(),
                    Arc::new(FilterChain::new(vec![])),
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
        time::delay_until(time::Instant::now().add(ttl)).await;

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
                    Metrics::default()
                        .new_session_metrics(&from, &endpoint.address)
                        .unwrap(),
                    Arc::new(FilterChain::new(vec![])),
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
        time::delay_until(time::Instant::now().add(ttl)).await;

        // poll, since cleanup is async, and may not have happened yet
        for _ in 1..10000 {
            time::delay_for(Duration::from_millis(1)).await;
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
