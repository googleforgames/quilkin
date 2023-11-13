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

/// On linux spawns a io-uring runtime + thread, everywhere else spawns a regular tokio task.
macro_rules! uring_spawn {
    ($future:expr) => {{
        let (tx, rx) = tokio::sync::oneshot::channel::<crate::Result<()>>();
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                std::thread::spawn(move || {
                    match tokio_uring::Runtime::new(&tokio_uring::builder().entries(2048)) {
                        Ok(runtime) => {
                            let _ = tx.send(Ok(()));
                            runtime.block_on($future);
                        }
                        Err(error) => {
                            let _ = tx.send(Err(error.into()));
                        }
                    };
                });
            } else {
                tokio::spawn(async move {
                    let _ = tx.send(Ok(()));
                    $future.await
                });
            }
        }
        rx
    }};
}

/// On linux spawns a io-uring task, everywhere else spawns a regular tokio task.
macro_rules! uring_inner_spawn {
    ($future:expr) => {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                tokio_uring::spawn($future);
            } else {
                tokio::spawn($future);
            }
        }
    };
}

pub mod cluster;
pub mod endpoint;
pub(crate) mod maxmind_db;
pub mod phoenix;
pub(crate) mod xds;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use socket2::{Protocol, Socket, Type};

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        use tokio_uring::net::UdpSocket;
    } else {
        use tokio::net::UdpSocket;
    }
}

pub use self::{
    cluster::ClusterMap,
    endpoint::{Endpoint, EndpointAddress},
};

fn socket_with_reuse_and_address(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            raw_socket_with_reuse_and_address(addr)
                .map(From::from)
                .map(UdpSocket::from_std)
        } else {
            epoll_socket_with_reuse_and_address(addr)
        }
    }
}

fn epoll_socket_with_reuse(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    raw_socket_with_reuse_and_address((Ipv6Addr::UNSPECIFIED, port).into())
        .map(From::from)
        .and_then(tokio::net::UdpSocket::from_std)
}

fn epoll_socket_with_reuse_and_address(addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    raw_socket_with_reuse_and_address(addr)
        .map(From::from)
        .and_then(tokio::net::UdpSocket::from_std)
}

pub(crate) fn raw_socket_with_reuse(port: u16) -> std::io::Result<Socket> {
    raw_socket_with_reuse_and_address((Ipv6Addr::UNSPECIFIED, port).into())
}

fn raw_socket_with_reuse_and_address(addr: SocketAddr) -> std::io::Result<Socket> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };

    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    enable_reuse(&sock)?;
    sock.set_nonblocking(true)?;
    if domain == socket2::Domain::IPV6 {
        // be explicit so we can have dual stack sockets.
        sock.set_only_v6(false)?;
    }
    sock.bind(&addr.into())?;
    Ok(sock)
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

/// An ipv6 socket that can accept and send data from either a local ipv4 address or ipv6 address
/// with port reuse enabled and only_v6 set to false.
pub struct DualStackLocalSocket {
    socket: UdpSocket,
    local_addr: SocketAddr,
}

impl DualStackLocalSocket {
    pub fn from_raw(socket: socket2::Socket) -> Self {
        let socket: std::net::UdpSocket = socket.into();
        let local_addr = socket.local_addr().unwrap();
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                let socket = UdpSocket::from_std(socket);
            } else {
                // This is only for macOS and Windows (non-production platforms),
                // and should never happen anyway, so unwrap here is fine.
                let socket = UdpSocket::from_std(socket).unwrap();
            }
        }
        Self { socket, local_addr }
    }

    pub fn new(port: u16) -> std::io::Result<Self> {
        raw_socket_with_reuse(port).map(Self::from_raw)
    }

    pub fn bind_local(port: u16) -> std::io::Result<Self> {
        let local_addr = (Ipv6Addr::LOCALHOST, port).into();
        let socket = socket_with_reuse_and_address(local_addr)?;
        Ok(Self { socket, local_addr })
    }

    pub fn local_ipv4_addr(&self) -> io::Result<SocketAddr> {
        Ok(match self.local_addr {
            SocketAddr::V4(_) => self.local_addr,
            SocketAddr::V6(_) => (Ipv4Addr::UNSPECIFIED, self.local_addr.port()).into(),
        })
    }

    pub fn local_ipv6_addr(&self) -> io::Result<SocketAddr> {
        Ok(match self.local_addr {
            SocketAddr::V4(v4addr) => SocketAddr::new(
                IpAddr::V6(v4addr.ip().to_ipv6_mapped()),
                self.local_addr.port(),
            ),
            SocketAddr::V6(_) => self.local_addr,
        })
    }

    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            pub async fn recv_from<B: tokio_uring::buf::IoBufMut>(&self, buf: B) -> (io::Result<(usize, SocketAddr)>, B) {
                self.socket.recv_from(buf).await
            }

            pub async fn send_to<B: tokio_uring::buf::IoBuf>(&self, buf: B, target: SocketAddr) -> (io::Result<usize>, B) {
                self.socket.send_to(buf, target).await
            }

            pub fn make_refcnt(self) -> std::rc::Rc<Self> {
                std::rc::Rc::new(self)
            }
        } else {
            pub async fn recv_from<B: std::ops::DerefMut<Target = [u8]>>(&self, mut buf: B) -> (io::Result<(usize, SocketAddr)>, B) {
                let result = self.socket.recv_from(&mut buf).await;
                (result, buf)
            }

            pub async fn send_to<B: std::ops::Deref<Target = [u8]>>(&self, buf: B, target: SocketAddr) -> (io::Result<usize>, B) {
                let result = self.socket.send_to(&buf, target).await;
                (result, buf)
            }

            pub fn make_refcnt(self) -> std::sync::Arc<Self> {
                std::sync::Arc::new(self)
            }
        }
    }
}

/// The same as DualStackSocket but uses epoll instead of uring.
#[derive(Debug)]
pub struct DualStackEpollSocket {
    socket: tokio::net::UdpSocket,
}

impl DualStackEpollSocket {
    pub fn new(port: u16) -> std::io::Result<Self> {
        Ok(Self {
            socket: epoll_socket_with_reuse(port)?,
        })
    }

    pub fn bind_local(port: u16) -> std::io::Result<Self> {
        Ok(Self {
            socket: epoll_socket_with_reuse_and_address((Ipv6Addr::LOCALHOST, port).into())?,
        })
    }

    /// Primarily used for testing of ipv4 vs ipv6 addresses.
    pub(crate) fn new_with_address(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            socket: epoll_socket_with_reuse_and_address(addr)?,
        })
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn local_ipv4_addr(&self) -> io::Result<SocketAddr> {
        let addr = self.socket.local_addr()?;
        match addr {
            SocketAddr::V4(_) => Ok(addr),
            SocketAddr::V6(_) => Ok((Ipv4Addr::UNSPECIFIED, addr.port()).into()),
        }
    }

    pub fn local_ipv6_addr(&self) -> io::Result<SocketAddr> {
        let addr = self.socket.local_addr()?;
        match addr {
            SocketAddr::V4(v4addr) => Ok(SocketAddr::new(
                IpAddr::V6(v4addr.ip().to_ipv6_mapped()),
                addr.port(),
            )),
            SocketAddr::V6(_) => Ok(addr),
        }
    }

    pub async fn send_to<A: tokio::net::ToSocketAddrs>(
        &self,
        buf: &[u8],
        target: A,
    ) -> io::Result<usize> {
        self.socket.send_to(buf, target).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use tokio::time::timeout;

    use crate::net::endpoint::address::AddressKind;
    use crate::test::{available_addr, AddressType, TestHelper};

    #[tokio::test]
    async fn dual_stack_socket_reusable() {
        let expected = available_addr(&AddressType::Random).await;
        let socket = super::DualStackEpollSocket::new(expected.port()).unwrap();
        let addr = socket.local_ipv4_addr().unwrap();

        match expected {
            SocketAddr::V4(_) => assert_eq!(expected, socket.local_ipv4_addr().unwrap()),
            SocketAddr::V6(_) => assert_eq!(expected, socket.local_ipv6_addr().unwrap()),
        }

        assert_eq!(expected.port(), socket.local_ipv4_addr().unwrap().port());
        assert_eq!(expected.port(), socket.local_ipv6_addr().unwrap().port());

        // should be able to do it a second time, since we are reusing the address.
        let socket = super::DualStackEpollSocket::new(expected.port()).unwrap();

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
        let addr = echo_addr.to_socket_addr().await.unwrap();

        socket.send_to(msg.as_bytes(), &addr).await.unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("should not timeout")
                .unwrap()
        );

        // try again, but from the opposite type of IP Address
        // Proof that a dual stack ipv6 socket can send to both ipv6 and ipv4.
        let ipv4_echo_addr = (Ipv4Addr::UNSPECIFIED, echo_addr.port).into();
        let opp_addr: SocketAddr = match echo_addr.host {
            AddressKind::Ip(ip) => match ip {
                IpAddr::V4(_) => (Ipv6Addr::UNSPECIFIED, echo_addr.port).into(),
                IpAddr::V6(_) => ipv4_echo_addr,
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

        // Since all other sockets are actual ipv6 sockets, let's force a test with a real ipv4 socket sending to our dual
        // stack socket.
        let (mut rx, socket) = t.open_ipv4_socket_and_recv_multiple_packets().await;
        socket
            .send_to(msg.as_bytes(), &ipv4_echo_addr)
            .await
            .unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("should not timeout")
                .unwrap()
        );
    }
}

/// Converts a a socket address to its canonical version.
/// This is just a copy of the method available in std but that is currently
/// nightly only.
pub fn to_canonical(addr: &mut SocketAddr) {
    let ip = match addr.ip() {
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                std::net::IpAddr::V4(mapped)
            } else {
                std::net::IpAddr::V6(ip)
            }
        }
        addr => addr,
    };

    addr.set_ip(ip);
}
