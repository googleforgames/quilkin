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

use std::{io, net::SocketAddr, net::ToSocketAddrs};

use socket2::{Protocol, Socket, Type};
use tokio::{net::UdpSocket, select};

use crate::Result;

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

    ///  Returns &[u8] from either of the buffers, depending on which address type (v4 vs v6) is
    /// used for communications.
    pub fn contents<'a>(v4_buf: &'a [u8], v6_buf: &'a [u8], recv: (usize, SocketAddr)) -> &'a [u8] {
        let (size, addr) = recv;
        match addr {
            SocketAddr::V4(_) => &v4_buf[..size],
            SocketAddr::V6(_) => &v6_buf[..size],
        }
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

    pub fn local_ipv6_addr(&self) -> io::Result<SocketAddr> {
        self.v6.local_addr()
    }

    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> io::Result<usize> {
        let mut addrs = target.to_socket_addrs()?;
        match addrs.next() {
            Some(target) => match target {
                SocketAddr::V4(_) => self.v4.send_to(buf, target).await,
                SocketAddr::V6(_) => self.v6.send_to(buf, target).await,
            },
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no addresses to send data to",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::{net::SocketAddr, time::Duration};

    use tokio::time::timeout;

    use crate::endpoint::address::AddressKind;
    use crate::test_utils::{available_addr, AddressType, TestHelper};

    #[tokio::test]
    async fn dual_stack_socket_reusable() {
        let expected = available_addr(&AddressType::Random).await;
        let socket = super::DualStackLocalSocket::new(expected.port()).unwrap();
        let addr = socket.local_ipv4_addr().unwrap();

        match expected {
            SocketAddr::V4(_) => assert_eq!(expected, socket.local_ipv4_addr().unwrap()),
            SocketAddr::V6(_) => assert_eq!(expected, socket.local_ipv6_addr().unwrap()),
        }

        assert_eq!(expected.port(), socket.local_ipv4_addr().unwrap().port());
        assert_eq!(expected.port(), socket.local_ipv6_addr().unwrap().port());

        // should be able to do it a second time, since we are reusing the address.
        let socket = super::DualStackLocalSocket::new(expected.port()).unwrap();

        match expected {
            SocketAddr::V4(_) => assert_eq!(expected, socket.local_ipv4_addr().unwrap()),
            SocketAddr::V6(_) => assert_eq!(expected, socket.local_ipv6_addr().unwrap()),
        }
        assert_eq!(addr.port(), socket.local_ipv4_addr().unwrap().port());
        assert_eq!(addr.port(), socket.local_ipv6_addr().unwrap().port());
    }

    #[tokio::test]
    async fn dual_stack_socket() {
        // Since the TestHelper uses the DualStackSocket, we can use it to test ourselves.
        let mut t = TestHelper::default();

        let echo_addr = t.run_echo_server(&AddressType::Random).await;
        let (mut rx, socket) = t.open_socket_and_recv_multiple_packets().await;

        let msg = "hello";
        socket
            .send_to(msg.as_bytes(), &echo_addr.to_socket_addr().await.unwrap())
            .await
            .unwrap();

        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("should not timeout")
                .unwrap()
        );

        // try again, but from the opposite type of IP Address
        let opp_addr: SocketAddr = match echo_addr.host {
            AddressKind::Ip(ip) => match ip {
                IpAddr::V4(_) => (Ipv6Addr::UNSPECIFIED, echo_addr.port).into(),
                IpAddr::V6(_) => (Ipv4Addr::UNSPECIFIED, echo_addr.port).into(),
            },
            // we're not testing this, since DNS resolves to IP.
            AddressKind::Name(_) => unreachable!(),
        };

        socket.send_to(msg.as_bytes(), &opp_addr).await.unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("should not timeout")
                .unwrap()
        );
    }
}
