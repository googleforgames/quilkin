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
use std::ops::AddAssign;
use std::str::from_utf8;
use std::sync::Arc;

use slog::{debug, error, info, o, warn, Logger};
use tokio::io::Result;
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{Duration, Instant};

use crate::config::{Config, ConnectionConfig};

/// SESSION_TIMEOUT_SECONDS is the default session timeout - which is one minute.
const SESSION_TIMEOUT_SECONDS: u64 = 60;

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
                error!(self.log, "Error processing receive socket"; "err" => err.to_string());
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
                    error!(log, "Error ensuring session exists: {}", err);
                    continue;
                }

                let map = sessions.read().await;
                let key = (recv_addr, *dest);
                match map.get(&key) {
                    Some(mtx) => {
                        let mut session = mtx.lock().await;
                        match session.send_to(packet).await {
                            Ok(_) => {
                                let mut expiration = session.expiration.write().await;
                                expiration.add_assign(Duration::new(SESSION_TIMEOUT_SECONDS, 0));
                            }
                            Err(err) => error!(log, "Error sending packet from session: {}", err),
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
                "origin" => packet.dest,
                "contents" => String::from_utf8(packet.contents.clone()).unwrap(),
            );

            if let Err(err) = send_socket
                .send_to(packet.contents.as_slice(), &packet.dest)
                .await
            {
                error!(log, "Error sending packet"; "dest" => packet.dest.to_string(), "err" => err.to_string());
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
            map.insert((from, dest), Mutex::new(s));
        }
        return Ok(());
    }
}

/// Packet represents a packet that needs to go somewhere
struct Packet {
    dest: SocketAddr,
    contents: Vec<u8>,
}

/// Session encapsulates a UDP stream session
struct Session {
    log: Logger,
    send: SendHalf,
    /// dest is where to send data to
    dest: SocketAddr,
    /// from is the original sender
    from: SocketAddr,
    /// session expiration timestamp
    expiration: Arc<RwLock<Instant>>,
}

impl Session {
    /// new creates a new Session, and starts the process of receiving udp sockets
    /// from its ephemeral port from endpoint(s)
    async fn new(
        base: &Logger,
        from: SocketAddr,
        dest: SocketAddr,
        sender: Sender<Packet>,
    ) -> Result<Self> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let (recv, send) = UdpSocket::bind(addr).await?.split();
        let mut s = Session {
            log: base.new(o!("source" => "server::Session", "from" => from, "dest" => dest)),
            send,
            from,
            dest,
            expiration: Arc::new(RwLock::new(
                Instant::now() + Duration::new(SESSION_TIMEOUT_SECONDS, 0),
            )),
        };
        debug!(s.log, "Session created");

        s.run(recv, sender);
        Ok(s)
    }

    /// run starts processing receiving udp packets on its UdpSocket
    fn run(&mut self, mut recv: RecvHalf, mut sender: Sender<Packet>) {
        let log = self.log.clone();
        let from = self.from;
        let expiration_mtx = self.expiration.clone();
        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            // TODO: shut this down once this session expires
            loop {
                debug!(log, "awaiting incoming packet");
                match recv.recv_from(&mut buf).await {
                    Err(err) => error!(log, "Error receiving packet: {}", err),
                    Ok((size, recv_addr)) => {
                        let packet = &buf[..size];
                        debug!(
                            log,
                            "Received packet from {}, {}",
                            recv_addr,
                            from_utf8(packet).unwrap()
                        );
                        match sender
                            .send(Packet {
                                contents: packet.to_vec(),
                                dest: from,
                            })
                            .await
                        {
                            Err(err) => {
                                println!("Error sending packet to channel: {}", err);
                            }
                            Ok(..) => {
                                let mut expiration = expiration_mtx.write().await;
                                expiration.add_assign(Duration::new(SESSION_TIMEOUT_SECONDS, 0));
                            }
                        }
                    }
                }
            }
        });
    }

    /// Sends a packet to the Session's dest.
    async fn send_to(&mut self, buf: &[u8]) -> Result<usize> {
        debug!(
            self.log,
            "Sending packet to: {}, {}",
            self.dest,
            from_utf8(buf).unwrap()
        );
        return self.send.send_to(buf, &self.dest).await;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::str::from_utf8;
    use std::sync::Arc;

    use slog::info;
    use tokio::net::udp::RecvHalf;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc::channel;
    use tokio::sync::{oneshot, RwLock};
    use tokio::time::Instant;

    use crate::config::{Config, ConnectionConfig, EndPoint, Local};
    use crate::logger;
    use crate::server::{Packet, Server, Session, SessionMap, SESSION_TIMEOUT_SECONDS};

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
        let log = logger();
        let (local_addr, wait) = assert_recv_udp().await;

        let config = Arc::new(Config {
            local: Local { port: 0 },
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
        let expiration = session.expiration.read().await;
        assert!(expiration.duration_since(Instant::now()).as_secs() >= SESSION_TIMEOUT_SECONDS);
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
        assert_eq!(from, sess.from);
        assert_eq!(dest, sess.dest);
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
            .send(Packet {
                dest: local_addr,
                contents: String::from("hello").into_bytes(),
            })
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
    async fn session_new() {
        let log = logger();
        let mut socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();
        let (send_packet, mut recv_packet) = channel::<Packet>(5);

        let mut sess = Session::new(&log, local_addr, local_addr, send_packet)
            .await
            .unwrap();

        let initial_expiration: Instant;
        {
            initial_expiration = sess.expiration.read().await.clone();
        }
        assert!(Instant::now() < initial_expiration);

        // echo the packet back again
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let (size, recv_addr) = socket.recv_from(&mut buf).await.unwrap();
            assert_eq!("hello", from_utf8(&buf[..size]).unwrap());
            socket.send_to(&buf[..size], recv_addr).await.unwrap();
        });

        sess.send_to("hello".as_bytes()).await.unwrap();

        let packet = recv_packet.recv().await.unwrap();
        assert_eq!(String::from("hello").into_bytes(), packet.contents);
        assert_eq!(local_addr, packet.dest);

        let current_expiration = sess.expiration.read().await.clone();
        assert!(Instant::now() < current_expiration);

        let diff = current_expiration.duration_since(initial_expiration);
        info!(log, "difference"; "duration" => format!("{:?}", diff));
        assert!(diff.as_secs() >= SESSION_TIMEOUT_SECONDS);
    }

    #[tokio::test]
    async fn session_send_to() {
        let log = logger();
        let (sender, _) = channel::<Packet>(1);
        let (local_addr, wait) = assert_recv_udp().await;

        let mut session = Session::new(&log, local_addr, local_addr, sender)
            .await
            .unwrap();
        session.send_to("hello".as_bytes()).await.unwrap();
        wait.await.unwrap();
    }

    /// assert_recv_udp asserts that the returned SockerAddr received a UDP packet
    /// with the contents of "hello"
    /// call wait.await.unwrap() to see if the message was received
    async fn assert_recv_udp() -> (SocketAddr, oneshot::Receiver<()>) {
        let socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();
        let (recv, _) = socket.split();
        let (done, wait) = oneshot::channel::<()>();
        recv_socket_done(recv, done);
        (local_addr, wait)
    }

    /// ephemeral_socket provides a socket bound to an ephemeral port
    async fn ephemeral_socket() -> UdpSocket {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        UdpSocket::bind(addr).await.unwrap()
    }

    /// recv_socket_done will send a value to done when receiving the "hello" UDP packet.
    fn recv_socket_done(mut recv: RecvHalf, done: oneshot::Sender<()>) {
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let size = recv.recv(&mut buf).await.unwrap();
            assert_eq!("hello", from_utf8(&buf[..size]).unwrap());
            done.send(()).unwrap();
        });
    }
}
