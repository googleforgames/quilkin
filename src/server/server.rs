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
use std::str::from_utf8;
use std::sync::Arc;

use slog::{debug, error, info, o, warn, Logger};
use tokio::io::Result;
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{delay_for, Duration, Instant};

use crate::config::{Config, ConnectionConfig};
use crate::server::sessions::{Packet, Session, SESSION_TIMEOUT_SECONDS};

type SessionMap = Arc<RwLock<HashMap<(SocketAddr, SocketAddr), Mutex<Session>>>>;

/// Server is the UDP server main implementation
pub struct Server {
    log: Logger,
}

impl Server {
    pub fn new(base: Logger) -> Self {
        let log = base.new(o!("source" => "server::Server"));
        return Server { log };
    }

    /// start the async processing of incoming UDP packets
    pub async fn run(self, config: Arc<Config>) -> Result<()> {
        self.log_config(&config);

        let (mut receive_socket, send_socket) = Server::bind(&config).await?.split();
        // HashMap key is from,destination addresses as a tuple.
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let (send_packets, receive_packets) = channel::<Packet>(1024);

        let log = self.log.clone();
        tokio::spawn(async move {
            Server::process_receive_packet_channel(&log, send_socket, receive_packets).await;
            debug!(log, "Receiver closed");
        });

        let log = self.log.clone();
        let prune_sessions = sessions.clone();
        // Pruning will occur ~ every interval period. So the timeout expiration may sometimes
        // exceed the expected, but we don't have to write lock the SessionMap as often to clean up.
        tokio::spawn(async move {
            loop {
                delay_for(Duration::from_secs(SESSION_TIMEOUT_SECONDS)).await;
                debug!(log, "Attempting to Prune Sessions");
                Server::prune_sessions(&log, prune_sessions.clone()).await;
            }
        });

        loop {
            if let Err(err) = Server::process_receive_socket(
                self.log.clone(),
                config.clone(),
                &mut receive_socket,
                sessions.clone(),
                send_packets.clone(),
            )
            .await
            {
                error!(self.log, "Error processing receive socket"; "err" => %err);
            }
        }
    }

    /// process_receive_socket takes packets from the local socket and asynchronously
    /// processes them to send them out to endpoints.
    async fn process_receive_socket(
        log: Logger,
        config: Arc<Config>,
        receive_socket: &mut RecvHalf,
        sessions: SessionMap,
        send_packets: Sender<Packet>,
    ) -> Result<()> {
        let mut buf: Vec<u8> = vec![0; 65535];
        let (size, recv_addr) = receive_socket.recv_from(&mut buf).await?;
        tokio::spawn(async move {
            let endpoints = config.get_endpoints();
            let packet = &buf[..size];

            debug!(
                log,
                "Packet Received from: {}, {}",
                recv_addr,
                from_utf8(packet).unwrap()
            );

            for (_, dest) in endpoints.iter() {
                if let Err(err) = Server::ensure_session(
                    &log,
                    sessions.clone(),
                    recv_addr,
                    *dest,
                    send_packets.clone(),
                )
                .await
                {
                    error!(log, "Error ensuring session exists"; "error" => %err);
                    continue;
                }

                let map = sessions.read().await;
                let key = (recv_addr, *dest);
                match map.get(&key) {
                    Some(mtx) => {
                        let mut session = mtx.lock().await;
                        match session.send_to(packet).await {
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
        });
        return Ok(());
    }

    /// process_receive_packet_channel blocks on receive_packets.recv() channel
    /// and sends each packet on to the Packet.dest
    async fn process_receive_packet_channel(
        log: &Logger,
        mut send_socket: SendHalf,
        mut receive_packets: Receiver<Packet>,
    ) {
        while let Some(packet) = receive_packets.recv().await {
            debug!(
                log,
                "Sending packet back to origin";
                "origin" => packet.dest(),
                "contents" => String::from_utf8(packet.contents().clone()).unwrap(),
            );

            if let Err(err) = send_socket
                .send_to(packet.contents().as_slice(), &packet.dest())
                .await
            {
                error!(log, "Error sending packet"; "dest" => %packet.dest(), "error" => %err);
            }
        }
    }

    /// log_config outputs a log of what is configured
    fn log_config(&self, config: &Arc<Config>) {
        info!(self.log, "Starting on port {}", config.local.port);
        match &config.connections {
            ConnectionConfig::Client { address, .. } => {
                info!(self.log, "Client proxy configuration"; "address" => address)
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
        sessions: SessionMap,
        from: SocketAddr,
        dest: SocketAddr,
        sender: Sender<Packet>,
    ) -> Result<()> {
        {
            let map = sessions.read().await;
            if map.contains_key(&(from, dest)) {
                return Ok(());
            }
        }
        let s = Session::new(log, from, dest, sender).await?;
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
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use slog::info;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc::channel;
    use tokio::sync::{oneshot, RwLock};
    use tokio::time;
    use tokio::time::{Duration, Instant};

    use crate::config::{Config, ConnectionConfig, EndPoint, Local};
    use crate::logger;
    use crate::server::sessions::{Packet, SESSION_TIMEOUT_SECONDS};
    use crate::server::test_utils::test::{assert_recv_udp, ephemeral_socket, recv_socket_done};

    #[tokio::test]
    async fn server_run_server() {
        let log = logger();
        let server = Server::new(log.clone());

        let socket1 = ephemeral_socket().await;
        let endpoint1 = socket1.local_addr().unwrap();
        let socket2 = ephemeral_socket().await;
        let endpoint2 = socket2.local_addr().unwrap();
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12358);

        let (recv1, mut send) = socket1.split();
        let (recv2, _) = socket2.split();
        let (done1, wait1) = oneshot::channel::<()>();
        let (done2, wait2) = oneshot::channel::<()>();

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

        tokio::spawn(async move {
            server.run(config).await.unwrap();
        });

        recv_socket_done(recv1, done1);
        recv_socket_done(recv2, done2);
        send.send_to("hello".as_bytes(), &local_addr).await.unwrap();
        wait1.await.unwrap();
        wait2.await.unwrap();
    }

    #[tokio::test]
    async fn server_run_client() {
        let log = logger();
        let server = Server::new(log.clone());
        let socket = ephemeral_socket().await;
        let endpoint_addr = socket.local_addr().unwrap();
        let (recv, mut send) = socket.split();
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357);
        let (done, wait) = oneshot::channel::<()>();
        let config = Arc::new(Config {
            local: Local {
                port: local_addr.port(),
            },
            filters: vec![],
            connections: ConnectionConfig::Client {
                address: endpoint_addr,
                connection_id: String::from(""),
            },
        });

        tokio::spawn(async move {
            server.run(config).await.unwrap();
        });

        recv_socket_done(recv, done);
        send.send_to("hello".as_bytes(), &local_addr).await.unwrap();
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn server_bind() {
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
    async fn server_process_receive_socket() {
        time::pause();

        let log = logger();
        let (local_addr, wait) = assert_recv_udp().await;

        let config = Arc::new(Config {
            local: Local { port: 0 },
            filters: vec![],
            connections: ConnectionConfig::Client {
                address: local_addr,
                connection_id: String::from(""),
            },
        });
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let receive_socket = UdpSocket::bind(addr).await.unwrap();
        let receive_addr = receive_socket.local_addr().unwrap();
        let (mut recv, mut send) = receive_socket.split();
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let (send_packets, mut recv_packets) = channel::<Packet>(1);

        let sessions_clone = sessions.clone();
        let log_clone = log.clone();

        let time_increment = 10;
        time::advance(Duration::from_secs(time_increment)).await;

        tokio::spawn(async move {
            Server::process_receive_socket(
                log_clone,
                config,
                &mut recv,
                sessions_clone,
                send_packets.clone(),
            )
            .await
        });

        send.send_to("hello".as_bytes(), &receive_addr)
            .await
            .unwrap();

        wait.await.unwrap();
        recv_packets.close();

        let map = sessions.read().await;
        assert_eq!(1, map.len());

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
                .as_secs()
        );

        time::resume();
    }

    #[tokio::test]
    async fn server_ensure_session() {
        let log = logger();
        let map: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:27890".parse().unwrap();
        let dest: SocketAddr = "127.0.0.1:27891".parse().unwrap();
        let (sender, mut recv) = channel::<Packet>(1);

        // gate
        {
            assert!(map.read().await.is_empty());
        }
        Server::ensure_session(&log, map.clone(), from, dest, sender)
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
    async fn server_process_receive_packet_channel() {
        let log = logger();
        let socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();

        let (recv_socket, send_socket) = socket.split();
        let (mut send_packet, recv_packet) = channel::<Packet>(5);
        let (done, wait) = oneshot::channel::<()>();

        recv_socket_done(recv_socket, done);

        if let Err(err) = send_packet
            .send(Packet::new(local_addr, String::from("hello").into_bytes()))
            .await
        {
            assert!(false, err)
        }

        tokio::spawn(async move {
            Server::process_receive_packet_channel(&log, send_socket, recv_packet).await;
        });
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn server_prune_sessions() {
        time::pause();
        let log = logger();
        let sessions: SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let to: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (send, _recv) = channel::<Packet>(1);

        Server::ensure_session(&log, sessions.clone(), from, to, send)
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
}
