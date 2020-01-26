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

use slog::{debug, error, info, o, Logger};
use tokio::io::Result;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

use crate::config::{Config, ConnectionConfig};
use std::str::from_utf8;

/// Server is the UDP server main implementation
pub struct Server {
    log: Logger,
}

impl Server {
    pub fn new(base: Logger) -> Self {
        let log = base.new(o!("source" => "server::Server"));
        return Server { log };
    }

    // TODO: write tests for this
    /// start the async processing of incoming UDP packets
    pub async fn run(self, config: Arc<Config>) -> Result<()> {
        info!(self.log, "Starting on port {}", config.local.port);
        match &config.connections {
            ConnectionConfig::Sender { address, .. } => {
                info!(self.log, "Sender configuration"; "address" => address)
            }
            ConnectionConfig::Receiver { endpoints } => {
                info!(self.log, "Receiver configuration"; "endpoints" => endpoints.len())
            }
        };

        let mut socket = Server::bind(&config).await?;
        let mut buf: Vec<u8> = vec![0; 65535];
        let sessions: Arc<RwLock<HashMap<String, Mutex<Session>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        loop {
            let (size, recv_addr) = socket.recv_from(&mut buf).await?;
            let packet = buf.clone();
            let log = self.log.clone();
            let config = config.clone();
            let local_sessions = sessions.clone();
            tokio::spawn(async move {
                let endpoints = config.get_endpoints();
                let packet = &packet[..size];

                debug!(
                    log,
                    "Packet Received from: {}, {}",
                    recv_addr,
                    from_utf8(packet).unwrap()
                );

                for (name, dest) in endpoints.iter() {
                    let _ = Server::ensure_session(&log, local_sessions.clone(), name, *dest)
                        .await
                        .map_err(|err| error!(log, "Error ensuring session exists: {}", err));

                    let map = local_sessions.read().await;
                    let mut session = map.get(name).unwrap().lock().await;
                    let _ = session
                        .send_to(packet)
                        .await
                        .map_err(|err| error!(log, "Error ensuring sending packet: {}", err));
                }
            });
        }
    }

    /// bind binds the local configured port
    async fn bind(config: &Config) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.local.port);
        return UdpSocket::bind(addr).await;
    }

    // TODO: write tests for this
    /// ensure_session makes sure there is a value session for the name in the sessions map
    async fn ensure_session(
        log: &Logger,
        sessions: Arc<RwLock<HashMap<String, Mutex<Session>>>>,
        name: &String,
        dest: SocketAddr,
    ) -> Result<()> {
        {
            let map = sessions.read().await;
            if map.contains_key(name) {
                return Ok(());
            }
        }
        let s = Session::new(log, name.clone(), dest).await?;
        {
            let mut map = sessions.write().await;
            map.insert(name.clone(), Mutex::new(s));
        }
        return Ok(());
    }
}

/// Session encapsulates a UDP stream session
struct Session {
    log: Logger,
    socket: UdpSocket,
    dest: SocketAddr,
    // TODO: store a session expiry, and update when you send data
}

impl Session {
    // TODO: write some tests
    async fn new(base: &Logger, name: String, dest: SocketAddr) -> Result<Self> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let s = Session {
            log: base.new(o!("source" => "server::Session", "name" => name, "dest" => dest)),
            socket: UdpSocket::bind(addr).await?,
            dest,
        };
        debug!(s.log, "Session created");
        return Ok(s);
    }

    // TODO: write some tests
    /// Both sends a packet to the Session's dest.
    async fn send_to(&mut self, buf: &[u8]) -> Result<usize> {
        debug!(
            self.log,
            "Sending packet to: {}, {}",
            self.dest,
            from_utf8(buf).unwrap()
        );
        return self.socket.send_to(buf, self.dest).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::config::{Config, ConnectionConfig, Local};
    use crate::server::Server;

    #[tokio::test]
    async fn bind() {
        let config = Config {
            local: Local { port: 12345 },
            connections: ConnectionConfig::Receiver {
                endpoints: Vec::new(),
            },
        };
        let socket = Server::bind(&config).await.unwrap();
        let addr = socket.local_addr().unwrap();

        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12345);
        assert_eq!(expected, addr)
    }
}
