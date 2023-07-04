/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::{io, net::SocketAddr};

use socket2::{Protocol, Socket, Type};
use tokio::{net::UdpSocket, select};

use crate::Result;

/// returns a UdpSocket with address and port reuse.
pub fn socket_with_reuse(port: u16) -> Result<UdpSocket> {
    socket_with_reuse_and_address((std::net::Ipv4Addr::UNSPECIFIED, port).into())
}

fn socket_with_reuse_and_address(addr: SocketAddr) -> Result<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    enable_reuse(&sock)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into()).map_err(|error| eyre::eyre!(error))
}

#[cfg(not(target_family = "windows"))]
fn enable_reuse(sock: &Socket) -> io::Result<()> {
    sock.set_reuse_port(true)?;
    Ok(())
}

#[cfg(target_family = "windows")]
fn enable_reuse(sock: &Socket) -> io::Result<()> {
    sock.set_reuse_address(true)?;
    Ok(())
}

/// Socket that can accept and send data from either a local ipv4 address or ipv6 address.
pub struct DualStackLocalSocket {
    v4: UdpSocket,
    v6: UdpSocket,
}

impl DualStackLocalSocket {
    pub fn new(port: u16) -> Result<DualStackLocalSocket> {
        // if ephemeral port, make sure they are on the same ports.
        if port == 0 {
            let v4 = socket_with_reuse_and_address((std::net::Ipv4Addr::UNSPECIFIED, port).into())?;
            let port = v4.local_addr()?.port();

            return Ok(Self {
                v4,
                v6: socket_with_reuse_and_address((std::net::Ipv6Addr::UNSPECIFIED, port).into())?,
            });
        }

        Ok(Self {
            v4: socket_with_reuse_and_address((std::net::Ipv4Addr::UNSPECIFIED, port).into())?,
            v6: socket_with_reuse_and_address((std::net::Ipv6Addr::UNSPECIFIED, port).into())?,
        })
    }

    // Receives datagrams from either an ipv4 address or ipv6. Match on the returned [`SocketAddr`] to
    // determine if the received data is in the ipv4_buf or ipv6_buf on a successful result.
    pub async fn recv_from(
        &self,
        v4_buf: &mut [u8],
        v6_buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr)> {
        select! {
            v4 = self.v4.recv_from(v4_buf) => {
                v4
            }
            v6 = self.v6.recv_from(v6_buf) => {
                v6
            }
        }
    }

    pub fn local_ipv4_addr(&self) -> io::Result<SocketAddr> {
        self.v4.local_addr()
    }

    pub fn local_ip6_addr(&self) -> io::Result<SocketAddr> {
        self.v6.local_addr()
    }

    pub async fn send_to(&self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        match target {
            SocketAddr::V4(_) => self.v4.send_to(buf, target).await,
            SocketAddr::V6(_) => self.v6.send_to(buf, target).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{available_addr, TestHelper};
    use crate::utils::net::DualStackLocalSocket;
    use std::net::SocketAddr;
    use std::str::from_utf8;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    #[tokio::test]
    async fn socket_with_reuse() {
        let expected = available_addr().await;
        let socket = super::socket_with_reuse(expected.port()).unwrap();
        let addr = socket.local_addr().unwrap();

        assert_eq!(expected, socket.local_addr().unwrap());

        // should be able to do it a second time, since we are reusing the address.
        let socket = super::socket_with_reuse(expected.port()).unwrap();
        let addr2 = socket.local_addr().unwrap();
        assert_eq!(addr, addr2);
    }

    #[tokio::test]
    async fn dual_domain_socket() {
        let mut t = TestHelper::default();

        let expected = available_addr().await;
        let socket = Arc::new(DualStackLocalSocket::new(expected.port()).unwrap());

        // TODO: when DualStackSocket is used everywhere, add a test for Ipv6 as well.
        let echo_addr = t.run_echo_server().await;

        let (packet_tx, packet_rx) = oneshot::channel::<String>();
        let socket_recv = socket.clone();
        tokio::spawn(async move {
            let mut v4_buf = vec![0; 1024];
            let mut v6_buf = vec![0; 1024];
            let (size, addr) = socket_recv
                .recv_from(&mut v4_buf, &mut v6_buf)
                .await
                .unwrap();

            let contents = match addr {
                SocketAddr::V4(_) => &v4_buf[..size],
                SocketAddr::V6(_) => &v6_buf[..size],
            };

            packet_tx
                .send(from_utf8(contents).unwrap().to_string())
                .unwrap();
        });

        let msg = "hello";
        socket
            .send_to(msg.as_bytes(), &echo_addr.to_socket_addr().await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), packet_rx)
                .await
                .expect("should not timeout")
                .unwrap()
        );
    }
}
