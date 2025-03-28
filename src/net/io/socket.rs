use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use socket2::{Protocol, Type};

use super::{completion, poll};

#[derive(Debug)]
#[repr(transparent)]
pub struct SystemSocket(socket2::Socket);

impl SystemSocket {
    #[track_caller]
    pub fn listen() -> std::io::Result<Self> {
        Self::from_port(0)
    }

    #[track_caller]
    pub fn from_port(port: u16) -> std::io::Result<Self> {
        Self::from_addr((std::net::Ipv6Addr::UNSPECIFIED, port).into())
    }

    #[track_caller]
    fn from_addr(addr: SocketAddr) -> std::io::Result<Self> {
        let domain = match addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };

        let sock = socket2::Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

        cfg_if::cfg_if! {
            if #[cfg(target_family = "windows")] {
                sock.set_reuse_address(true)?;
            } else {
                sock.set_reuse_port(true)?;
            }
        }

        sock.set_nonblocking(true)?;
        if domain == socket2::Domain::IPV6 {
            // be explicit so we can have dual stack sockets.
            sock.set_only_v6(false)?;
        }
        sock.bind(&addr.into())?;

        Ok(Self(sock))
    }

    #[inline]
    #[track_caller]
    pub fn port(&self) -> u16 {
        match self.0.local_addr().unwrap().as_socket().unwrap() {
            SocketAddr::V4(addr) => addr.port(),
            SocketAddr::V6(addr) => addr.port(),
        }
    }

    pub fn into_inner(self) -> socket2::Socket {
        self.0
    }
}

impl std::ops::Deref for SystemSocket {
    type Target = socket2::Socket;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An ipv6 socket that can accept and send data from either a local ipv4 address or ipv6 address
/// with port reuse enabled and `only_v6` set to false.
#[derive(Debug)]
pub struct Socket {
    socket: SocketKind,
    local_addr: SocketAddr,
}

#[derive(Debug)]
enum SocketKind {
    Completion(completion::Socket),
    Polling(poll::Socket),
}

impl Socket {
    pub fn polling(socket: SystemSocket) -> Self {
        let socket = poll::from_system_socket(socket);
        let local_addr = socket.local_addr().unwrap();
        Self {
            socket: SocketKind::Polling(socket),
            local_addr,
        }
    }

    pub fn polling_from_addr(addr: SocketAddr) -> std::io::Result<Self> {
        SystemSocket::from_addr(addr).map(Self::polling)
    }

    pub fn polling_from_port(port: u16) -> std::io::Result<Self> {
        Self::polling_from_addr((std::net::Ipv6Addr::UNSPECIFIED, port).into())
    }

    pub fn polling_listen() -> std::io::Result<Self> {
        Self::polling_from_port(0)
    }

    pub fn completion(socket: SystemSocket) -> Self {
        let socket = completion::from_system_socket(socket);
        let local_addr = socket.local_addr().unwrap();
        Self {
            socket: SocketKind::Completion(socket),
            local_addr,
        }
    }

    pub fn completion_from_addr(addr: SocketAddr) -> std::io::Result<Self> {
        SystemSocket::from_addr(addr).map(Self::completion)
    }

    pub fn completion_from_port(port: u16) -> std::io::Result<Self> {
        Self::completion_from_addr((std::net::Ipv6Addr::UNSPECIFIED, port).into())
    }

    pub fn completion_listen() -> std::io::Result<Self> {
        Self::completion_from_port(0)
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn local_ipv4_addr(&self) -> SocketAddr {
        match self.local_addr {
            SocketAddr::V4(_) => self.local_addr,
            SocketAddr::V6(_) => (Ipv4Addr::UNSPECIFIED, self.local_addr.port()).into(),
        }
    }

    pub fn local_ipv6_addr(&self) -> SocketAddr {
        match self.local_addr {
            SocketAddr::V4(v4addr) => SocketAddr::new(
                IpAddr::V6(v4addr.ip().to_ipv6_mapped()),
                self.local_addr.port(),
            ),
            SocketAddr::V6(_) => self.local_addr,
        }
    }

    pub async fn recv_from<B: std::ops::DerefMut<Target = [u8]>>(
        &self,
        mut buf: B,
    ) -> std::io::Result<(usize, SocketAddr)> {
        match &self.socket {
            SocketKind::Completion(socket) => socket.recv_from(&mut buf),
            SocketKind::Polling(socket) => socket.recv_from(&mut buf).await,
        }
    }

    pub async fn send_to<B: std::ops::Deref<Target = [u8]>>(
        &self,
        buf: B,
        target: SocketAddr,
    ) -> std::io::Result<usize> {
        match &self.socket {
            SocketKind::Completion(socket) => socket.send_to(&buf, target),
            SocketKind::Polling(socket) => socket.send_to(&buf, target).await,
        }
    }
}

impl std::os::fd::AsRawFd for Socket {
    fn as_raw_fd(&self) -> i32 {
        match &self.socket {
            SocketKind::Completion(socket) => socket.as_raw_fd(),
            SocketKind::Polling(socket) => socket.as_raw_fd(),
        }
    }
}
