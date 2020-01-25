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

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::from_utf8;
use std::sync::Arc;

use slog::{debug, error, info, o, Logger};
use tokio::io::Result;
use tokio::net::UdpSocket;

use crate::config::{Config, ConnectionConfig};

/// Server is the UDP server main implementation
pub struct Server {
    log: Logger,
}

impl Server {
    pub fn new(base: Logger) -> Self {
        let log = base.new(o!("source" => "server::Server"));
        return Server { log };
    }

    /// start the async processing of UDP packets
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
        loop {
            debug!(self.log, "awaiting packet");
            let (size, addr) = socket.recv_from(&mut buf).await?;
            let result = buf.clone();
            let async_log = self.log.clone();
            tokio::spawn(
                async move { Server::receive_packet(async_log, &result[..size], addr).await },
            );
        }
    }

    /// bind binds the local configured port
    async fn bind(config: &Config) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), config.local.port);
        return UdpSocket::bind(addr).await;
    }

    /// receive_packet provides the logic for what to do when a packet comes in!
    async fn receive_packet(log: Logger, buf: &[u8], addr: SocketAddr) -> Result<()> {
        let s = from_utf8(buf).unwrap();
        info!(log, "Packet Received from {}: {}", addr, s);
        return Ok(());
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

        let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        assert_eq!(expected, addr)
    }
}
