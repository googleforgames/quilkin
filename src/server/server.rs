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
use std::io::{Error as IOError, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::from_utf8;
use std::sync::Arc;

use slog::{debug, error, info, o, warn, Logger};
use tokio::io::Result;
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{delay_for, Duration, Instant};

use crate::config::{Config, ConnectionConfig, EndPoint};
use crate::extensions::{Filter, FilterChain, FilterRegistry};
use crate::load_balancer_policy::LoadBalancerPolicy;
use crate::server::sessions::{Packet, Session, SESSION_TIMEOUT_SECONDS};

use super::metrics::{start_metrics_server, Metrics};

type SessionMap = Arc<RwLock<HashMap<(SocketAddr, SocketAddr), Mutex<Session>>>>;

/// Server is the UDP server main implementation
pub struct Server {
    log: Logger,
    /// registry for the set of available filters
    filter_registry: FilterRegistry,
    metrics: Metrics,
}

impl Server {
    /// new Server. Takes a logger, and the registry of available Filters.
    pub fn new(base: Logger, filter_registry: FilterRegistry, metrics: Metrics) -> Self {
        let log = base.new(o!("source" => "server::Server"));
        return Server {
            log,
            filter_registry,
            metrics,
        };
    }

    /// start the async processing of incoming UDP packets. Will block until an
    /// event is sent through the stop Receiver.
    pub async fn run(self, config: Arc<Config>, stop: oneshot::Receiver<()>) -> Result<()> {
        self.log_config(&config);

        // Start metrics server if needed - it is shutdown before exiting the function.
        let metrics_shutdown_tx = self.metrics.addr.map(|addr| {
            let (metrics_shutdown_tx, metrics_shutdown_rx) = oneshot::channel();
            start_metrics_server(
                addr,
                self.metrics.registry.clone(),
                metrics_shutdown_rx,
                self.log.clone(),
            );
            metrics_shutdown_tx
        });

        let (receive_socket, send_socket) = Server::bind(&config).await?.split();
        // HashMap key is from,destination addresses as a tuple.
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let (send_packets, receive_packets) = mpsc::channel::<Packet>(1024);
        let chain = Arc::new(FilterChain::from_config(
            config.clone(),
            &self.filter_registry,
        )?);

        self.run_receive_packet(chain.clone(), send_socket, receive_packets);
        self.run_prune_sessions(&sessions);
        self.run_recv_from(
            Arc::new(LoadBalancerPolicy::new(&config.connections)),
            chain,
            receive_socket,
            &sessions,
            send_packets,
        );

        // convert to an IO error
        let result = stop
            .await
            .map_err(|err| IOError::new(ErrorKind::BrokenPipe, err));

        metrics_shutdown_tx.map(|tx| tx.send(()).ok());
        result
    }

    /// run_prune_sessions starts the timer for pruning sessions and runs prune_sessions every
    /// SESSION_TIMEOUT_SECONDS, via a tokio::spawn, i.e. it's non-blocking.
    /// Pruning will occur ~ every interval period. So the timeout expiration may sometimes
    /// exceed the expected, but we don't have to write lock the SessionMap as often to clean up.
    fn run_prune_sessions(&self, sessions: &SessionMap) {
        let log = self.log.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            loop {
                delay_for(Duration::from_secs(SESSION_TIMEOUT_SECONDS)).await;
                debug!(log, "Attempting to Prune Sessions");
                Server::prune_sessions(&log, sessions.clone()).await;
            }
        });
    }

    // run_recv_from is a non blocking function that continually runs
    // Server::recv_from() to process new incoming packets.
    fn run_recv_from(
        &self,
        lb_policy: Arc<LoadBalancerPolicy>,
        chain: Arc<FilterChain>,
        mut receive_socket: RecvHalf,
        sessions: &SessionMap,
        send_packets: mpsc::Sender<Packet>,
    ) {
        let sessions = sessions.clone();
        let log = self.log.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            loop {
                if let Err(err) = Server::recv_from(
                    &log,
                    &metrics,
                    lb_policy.clone(),
                    chain.clone(),
                    &mut receive_socket,
                    sessions.clone(),
                    send_packets.clone(),
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
        log: &Logger,
        metrics: &Metrics,
        lb_policy: Arc<LoadBalancerPolicy>,
        chain: Arc<FilterChain>,
        receive_socket: &mut RecvHalf,
        sessions: SessionMap,
        send_packets: mpsc::Sender<Packet>,
    ) -> Result<()> {
        let mut buf: Vec<u8> = vec![0; 65535];
        let (size, recv_addr) = receive_socket.recv_from(&mut buf).await?;
        let log = log.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let packet = &buf[..size];

            debug!(
                log,
                "Packet Received from: {}, {}",
                recv_addr,
                from_utf8(packet).unwrap()
            );

            let result = chain.local_receive_filter(
                &lb_policy.choose_endpoints(),
                recv_addr,
                packet.to_vec(),
            );

            if let Some((endpoints, packet)) = result {
                for endpoint in endpoints.iter() {
                    if let Err(err) = Server::ensure_session(
                        &log,
                        &metrics,
                        chain.clone(),
                        sessions.clone(),
                        recv_addr,
                        &endpoint,
                        send_packets.clone(),
                    )
                    .await
                    {
                        error!(log, "Error ensuring session exists"; "error" => %err);
                        continue;
                    }

                    let map = sessions.read().await;
                    let key = (recv_addr, endpoint.address);
                    match map.get(&key) {
                        Some(mtx) => {
                            let mut session = mtx.lock().await;
                            match session.send_to(packet.as_slice()).await {
                                Ok(_) => {
                                    session.increment_expiration().await;
                                }
                                Err(err) => {
                                    error!(log, "Error sending packet from session"; "error" => %err)
                                }
                            };
                        }
                        None => warn!(
                            log,
                            "Could not find session for key: ({}:{})",
                            key.0.to_string(),
                            key.1.to_string()
                        ),
                    }
                }
            }
        });
        Ok(())
    }

    /// run_receive_packet is a non-blocking loop on receive_packets.recv() channel
    /// and sends each packet on to the Packet.dest
    fn run_receive_packet(
        &self,
        chain: Arc<FilterChain>,
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
                    "contents" => String::from_utf8(packet.contents().clone()).unwrap(),
                );

                if let Some(data) =
                    chain.local_send_filter(packet.dest(), packet.contents().to_vec())
                {
                    if let Err(err) = send_socket.send_to(data.as_slice(), &packet.dest()).await {
                        error!(log, "Error sending packet"; "dest" => %packet.dest(), "error" => %err);
                    }
                }
            }
            debug!(log, "Receiver closed");
        });
    }

    /// log_config outputs a log of what is configured
    fn log_config(&self, config: &Arc<Config>) {
        info!(self.log, "Starting on port {}", config.local.port);
        match &config.connections {
            ConnectionConfig::Client { addresses, .. } => {
                info!(self.log, "Client proxy configuration"; "address" => format!("{:?}", addresses))
            }
            ConnectionConfig::Server { endpoints } => {
                info!(self.log, "Server proxy configuration"; "endpoints" => endpoints.len())
            }
        };
    }

    /// bind binds the local configured port
    async fn bind(config: &Config) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.local.port);
        return UdpSocket::bind(addr).await;
    }

    /// ensure_session makes sure there is a value session for the name in the sessions map
    async fn ensure_session(
        log: &Logger,
        metrics: &Metrics,
        chain: Arc<FilterChain>,
        sessions: SessionMap,
        from: SocketAddr,
        dest: &EndPoint,
        sender: mpsc::Sender<Packet>,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        {
            let map = sessions.read().await;
            if map.contains_key(&(from, dest.address)) {
                return Ok(());
            }
        }
        let s = Session::new(
            log,
            metrics.new_session_metrics(&from, &dest.address)?,
            chain,
            from,
            dest.clone(),
            sender,
        )
        .await?;
        {
            let mut map = sessions.write().await;
            map.insert(s.key(), Mutex::new(s));
        }
        return Ok(());
    }

    /// prune_sessions removes expired Sessions from the SessionMap.
    /// Should be run on a time interval.
    /// This will lock the SessionMap if it finds expired sessions
    async fn prune_sessions(log: &Logger, sessions: SessionMap) {
        let mut remove_keys = Vec::<(SocketAddr, SocketAddr)>::new();
        {
            let now = Instant::now();
            let map = sessions.read().await;
            for (k, v) in map.iter() {
                let session = v.lock().await;
                let expiration = session.expiration().await;
                if expiration.lt(&now) {
                    let value = k.clone();
                    remove_keys.push(value);
                }
            }
        }

        if !remove_keys.is_empty() {
            let mut map = sessions.write().await;
            for key in remove_keys.iter() {
                if let Some(session) = map.get(key) {
                    let sess = session.lock().await;
                    if let Err(err) = sess.close() {
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

    use serde_yaml::Value;
    use slog::info;
    use tokio::sync::{mpsc, oneshot, RwLock};
    use tokio::time;
    use tokio::time::{Duration, Instant};

    use crate::config;
    use crate::config::{Config, ConnectionConfig, ConnectionId, EndPoint, Local};
    use crate::extensions::default_registry;
    use crate::server::sessions::{Packet, SESSION_TIMEOUT_SECONDS};
    use crate::test_utils::{
        ephemeral_socket, logger, recv_udp, recv_udp_done, TestFilter, TestFilterFactory,
    };

    use super::*;

    #[tokio::test]
    async fn run_server() {
        let log = logger();
        let server = Server::new(log.clone(), FilterRegistry::new(), Metrics::default());

        let socket1 = ephemeral_socket().await;
        let endpoint1 = socket1.local_addr().unwrap();
        let socket2 = ephemeral_socket().await;
        let endpoint2 = socket2.local_addr().unwrap();
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12358);

        let (recv1, mut send) = socket1.split();
        let (recv2, _) = socket2.split();
        let (done1, wait1) = oneshot::channel::<String>();
        let (done2, wait2) = oneshot::channel::<String>();

        let config = Arc::new(Config {
            local: Local {
                port: local_addr.port(),
            },
            filters: vec![],
            connections: ConnectionConfig::Server {
                endpoints: vec![
                    EndPoint {
                        name: String::from("e1"),
                        address: endpoint1.clone(),
                        connection_ids: vec![],
                    },
                    EndPoint {
                        name: String::from("e2"),
                        address: endpoint2.clone(),
                        connection_ids: vec![],
                    },
                ],
            },
        });

        let (close, stop) = oneshot::channel::<()>();
        tokio::spawn(async move {
            server.run(config, stop).await.unwrap();
        });

        let msg = "hello";
        recv_udp_done(recv1, done1);
        recv_udp_done(recv2, done2);
        send.send_to(msg.as_bytes(), &local_addr).await.unwrap();
        assert_eq!(msg, wait1.await.unwrap());
        assert_eq!(msg, wait2.await.unwrap());
        close.send(()).unwrap();
    }

    #[tokio::test]
    async fn run_client() {
        let log = logger();
        let server = Server::new(log.clone(), FilterRegistry::new(), Metrics::default());
        let socket = ephemeral_socket().await;
        let endpoint_addr = socket.local_addr().unwrap();
        let (recv, mut send) = socket.split();
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357);
        let (done, wait) = oneshot::channel::<String>();
        let config = Arc::new(Config {
            local: Local {
                port: local_addr.port(),
            },
            filters: vec![],
            connections: ConnectionConfig::Client {
                addresses: vec![endpoint_addr],
                connection_id: ConnectionId::new(),
                lb_policy: None,
            },
        });

        let (close, stop) = oneshot::channel::<()>();
        tokio::spawn(async move {
            server.run(config, stop).await.unwrap();
        });

        let msg = "hello";
        recv_udp_done(recv, done);
        send.send_to(msg.as_bytes(), &local_addr).await.unwrap();
        assert_eq!(msg, wait.await.unwrap());

        close.send(()).unwrap();
    }

    #[tokio::test]
    async fn run_with_filter() {
        let log = logger();
        let mut registry = FilterRegistry::new();
        registry.insert(TestFilterFactory {});

        let server = Server::new(log.clone(), registry, Metrics::default());
        let socket = ephemeral_socket().await;
        let endpoint_addr = socket.local_addr().unwrap();
        let (recv, mut send) = socket.split();
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12367);
        let (done, wait) = oneshot::channel::<String>();
        let config = Arc::new(Config {
            local: Local {
                port: local_addr.port(),
            },
            filters: vec![config::Filter {
                name: "TestFilter".to_string(),
                config: Value::Null,
            }],
            connections: ConnectionConfig::Client {
                addresses: vec![endpoint_addr],
                connection_id: ConnectionId::new(),
                lb_policy: None,
            },
        });

        let (close, stop) = oneshot::channel::<()>();
        tokio::spawn(async move {
            server.run(config, stop).await.unwrap();
        });

        let msg = "hello";
        recv_udp_done(recv, done);
        send.send_to(msg.as_bytes(), &local_addr).await.unwrap();

        // since we don't know what the session ephemeral port is, we'll just
        // search for the filter strings.
        let result = wait.await.unwrap();
        assert!(
            result.contains(msg),
            format!("'{}' not found in '{}'", msg, result)
        );
        assert!(
            result.contains(":lrf:"),
            format!(":lrf: not found in '{}'", result)
        );
        assert!(
            result.contains(":esf:"),
            format!(":esf: not found in '{}'", result)
        );

        close.send(()).unwrap();
    }

    #[tokio::test]
    async fn bind() {
        let config = Config {
            local: Local { port: 12345 },
            filters: vec![],
            connections: ConnectionConfig::Server {
                endpoints: Vec::new(),
            },
        };
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

        async fn test(
            name: String,
            log: &Logger,
            chain: Arc<FilterChain>,
            expected: Expected,
        ) -> Result {
            info!(log, "Test"; "name" => name);
            let msg = "hello".to_string();
            let (local_addr, wait) = recv_udp().await;

            let lb_policy = Arc::new(LoadBalancerPolicy::new(&ConnectionConfig::Client {
                addresses: vec![local_addr],
                connection_id: ConnectionId::new(),
                lb_policy: None,
            }));
            let receive_socket = ephemeral_socket().await;
            let receive_addr = receive_socket.local_addr().unwrap();
            let (mut recv, mut send) = receive_socket.split();
            let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
            let (send_packets, mut recv_packets) = mpsc::channel::<Packet>(1);

            let sessions_clone = sessions.clone();
            let log_clone = log.clone();

            let time_increment = 10;
            time::advance(Duration::from_secs(time_increment)).await;

            tokio::spawn(async move {
                Server::recv_from(
                    &log_clone,
                    &Metrics::default(),
                    lb_policy,
                    chain,
                    &mut recv,
                    sessions_clone,
                    send_packets.clone(),
                )
                .await
            });

            send.send_to(msg.as_bytes(), &receive_addr).await.unwrap();

            let result = wait.await.unwrap();
            recv_packets.close();

            let map = sessions.read().await;
            assert_eq!(expected.session_len, map.len());

            // need to switch to 127.0.0.1, as the request comes locally
            let mut receive_addr_local = receive_addr.clone();
            receive_addr_local.set_ip("127.0.0.1".parse().unwrap());
            let build_key = (receive_addr_local, local_addr);
            assert!(map.contains_key(&build_key));
            let session = map.get(&build_key).unwrap().lock().await;
            assert_eq!(
                SESSION_TIMEOUT_SECONDS,
                session
                    .expiration()
                    .await
                    .duration_since(Instant::now())
                    .as_secs(),
            );

            Result {
                msg: result,
                addr: receive_addr_local,
            }
        }

        let log = logger();

        let chain = Arc::new(FilterChain::new(vec![]));
        let result = test(
            "no filter".to_string(),
            &log,
            chain,
            Expected { session_len: 1 },
        )
        .await;
        assert_eq!("hello", result.msg);

        let chain = Arc::new(FilterChain::new(vec![Box::new(TestFilter {})]));
        let result = test(
            "test filter".to_string(),
            &log,
            chain,
            Expected { session_len: 2 },
        )
        .await;

        assert_eq!(
            format!(
                "hello:lrf:127.0.0.1:{}:esf:address-0:127.0.0.1:{}",
                result.addr.port(),
                result.addr.port()
            ),
            result.msg
        );

        time::resume();
    }

    #[tokio::test]
    async fn run_recv_from() {
        let log = logger();
        let msg = "hello";
        let server = Server::new(log.clone(), default_registry(&log), Metrics::default());
        let (local_addr, wait) = recv_udp().await;
        let lb_policy = Arc::new(LoadBalancerPolicy::new(&ConnectionConfig::Client {
            addresses: vec![local_addr],
            connection_id: ConnectionId::new(),
            lb_policy: None,
        }));
        let socket = ephemeral_socket().await;
        let addr = socket.local_addr().unwrap();
        let (recv, mut send) = socket.split();
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let (send_packets, mut recv_packets) = mpsc::channel::<Packet>(1);

        server.run_recv_from(
            lb_policy,
            Arc::new(FilterChain::new(vec![])),
            recv,
            &sessions,
            send_packets,
        );

        send.send_to(msg.as_bytes(), &addr).await.unwrap();
        assert_eq!(msg, wait.await.unwrap());
        recv_packets.close();
    }

    #[tokio::test]
    async fn ensure_session() {
        let log = logger();
        let map: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:27890".parse().unwrap();
        let dest: SocketAddr = "127.0.0.1:27891".parse().unwrap();
        let (sender, mut recv) = mpsc::channel::<Packet>(1);
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: dest,
            connection_ids: vec![],
        };

        // gate
        {
            assert!(map.read().await.is_empty());
        }
        Server::ensure_session(
            &log,
            &Metrics::default(),
            Arc::new(FilterChain::new(vec![])),
            map.clone(),
            from,
            &endpoint,
            sender,
        )
        .await
        .unwrap();

        let rmap = map.read().await;
        let key = (from, dest);
        assert!(rmap.contains_key(&key));

        let sess = rmap.get(&key).unwrap().lock().await;
        assert_eq!(key, sess.key());
        assert_eq!(1, rmap.keys().len());

        recv.close();
    }

    #[tokio::test]
    async fn run_receive_packet() {
        let server = Server::new(logger(), FilterRegistry::new(), Metrics::default());
        let msg = "hello";

        // without a filter
        let socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();

        let (recv_socket, send_socket) = socket.split();
        let (mut send_packet, recv_packet) = mpsc::channel::<Packet>(5);
        let (done, wait) = oneshot::channel::<String>();

        recv_udp_done(recv_socket, done);

        if let Err(err) = send_packet
            .send(Packet::new(local_addr, msg.as_bytes().to_vec()))
            .await
        {
            assert!(false, err)
        }

        server.run_receive_packet(Arc::new(FilterChain::new(vec![])), send_socket, recv_packet);
        assert_eq!(msg, wait.await.unwrap());

        // with a filter
        let socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();

        let (recv_socket, send_socket) = socket.split();
        let (mut send_packet, recv_packet) = mpsc::channel::<Packet>(5);
        let (done, wait) = oneshot::channel::<String>();

        recv_udp_done(recv_socket, done);

        send_packet
            .send(Packet::new(local_addr, msg.as_bytes().to_vec()))
            .await
            .map_err(|err| assert!(false, err))
            .unwrap();

        server.run_receive_packet(
            Arc::new(FilterChain::new(vec![Box::new(TestFilter {})])),
            send_socket,
            recv_packet,
        );
        assert_eq!(format!("{}:lsf:{}", msg, local_addr), wait.await.unwrap());
    }

    #[tokio::test]
    async fn prune_sessions() {
        time::pause();
        let log = logger();
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let to: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (send, _recv) = mpsc::channel::<Packet>(1);
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: to,
            connection_ids: vec![],
        };

        Server::ensure_session(
            &log,
            &Metrics::default(),
            Arc::new(FilterChain::new(vec![])),
            sessions.clone(),
            from,
            &endpoint,
            send,
        )
        .await
        .unwrap();

        let key = (from, to);
        // gate, to ensure valid state
        {
            let map = sessions.read().await;

            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // session map should be the same since, we haven't passed expiry
        time::advance(Duration::new(SESSION_TIMEOUT_SECONDS / 2, 0)).await;
        Server::prune_sessions(&log, sessions.clone()).await;
        {
            let map = sessions.read().await;
            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        time::advance(Duration::new(2 * SESSION_TIMEOUT_SECONDS, 0)).await;
        Server::prune_sessions(&log, sessions.clone()).await;
        {
            let map = sessions.read().await;
            assert!(
                !map.contains_key(&key),
                "should not contain the key after prune"
            );
            assert_eq!(0, map.len(), "len should be 0, bit is {}", map.len());
        }
        info!(log, "test complete");
        time::resume();
    }

    #[tokio::test]
    async fn run_prune_sessions() {
        time::pause();
        let log = logger();
        let server = Server::new(log.clone(), default_registry(&log), Metrics::default());
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let to: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (send, _recv) = mpsc::channel::<Packet>(1);
        let key = (from, to);
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: to,
            connection_ids: vec![],
        };

        server.run_prune_sessions(&sessions);
        Server::ensure_session(
            &log,
            &Metrics::default(),
            Arc::new(FilterChain::new(vec![])),
            sessions.clone(),
            from,
            &endpoint,
            send,
        )
        .await
        .unwrap();

        // session map should be the same since, we haven't passed expiry
        time::advance(Duration::new(SESSION_TIMEOUT_SECONDS / 2, 0)).await;
        {
            let map = sessions.read().await;

            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }
        time::advance(Duration::new(2 * SESSION_TIMEOUT_SECONDS, 0)).await;

        // poll, since cleanup is async, and may not have happened yet
        for _ in 1..10 {
            time::delay_for(Duration::from_secs(1)).await;
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
