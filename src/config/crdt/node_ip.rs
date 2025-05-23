use std::fmt;

/// `NodeIp` is always stored as an IPv6 address rather than a `std::net::IpAddr`
/// as it can represent an IPv4 address but we don't take the hit of a discriminant
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    //bincode::Encode,
    //bincode::Decode,
    serde::Serialize,
)]
#[serde(transparent)]
pub struct NodeIp(pub std::net::Ipv6Addr);

impl NodeIp {
    pub fn local_ip() -> Result<Self, UnknownIp> {
        // Use the Cloudflare DNS as the external IP to connect to to determine the
        // address used to connect to it. This _might_ not be the same as the IP
        // used in intracluster communication.
        const IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(1, 1, 1, 1);
        const IPV6: std::net::Ipv6Addr =
            std::net::Ipv6Addr::new(2606, 4700, 4700, 0, 0, 0, 0, 1111);

        fn ipv6() -> Option<std::net::IpAddr> {
            let socket = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).ok()?;
            socket.connect((IPV6, 80)).ok()?;
            Some(socket.local_addr().ok()?.ip())
        }

        if let Some(ipv6) = ipv6() {
            return Ok(ipv6.into());
        }

        fn ipv4() -> Result<std::net::IpAddr, UnknownIp> {
            let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
                .map_err(|err| UnknownIp { err, op: "bind" })?;
            socket
                .connect((IPV4, 80))
                .map_err(|err| UnknownIp { err, op: "connect" })?;
            Ok(socket
                .local_addr()
                .map_err(|err| UnknownIp {
                    err,
                    op: "gethostname",
                })?
                .ip())
        }

        ipv4().map(Self::from)
    }

    #[inline]
    pub const fn is_ipv4_mapped(&self) -> bool {
        matches!(self.0.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
    }

    #[inline]
    pub fn to_socket_addr(self, port: u16) -> std::net::SocketAddr {
        if let Some(ipv4) = self.0.to_ipv4_mapped() {
            (ipv4, port).into()
        } else {
            (self.0, port).into()
        }
    }
}

impl Default for NodeIp {
    fn default() -> Self {
        Self(std::net::Ipv6Addr::from_bits(0))
    }
}

impl PartialEq<std::net::IpAddr> for NodeIp {
    fn eq(&self, other: &std::net::IpAddr) -> bool {
        match other {
            std::net::IpAddr::V4(v4) => {
                let Some(ipv4) = self.0.to_ipv4_mapped() else {
                    return false;
                };
                v4 == &ipv4
            }
            std::net::IpAddr::V6(v6) => v6 == &self.0,
        }
    }
}

impl fmt::Debug for NodeIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for NodeIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for NodeIp {
    type Err = std::net::AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse::<std::net::Ipv6Addr>() {
            Ok(Self(ip))
        } else {
            s.parse::<std::net::Ipv4Addr>().map(Self::from)
        }
    }
}

impl From<std::net::IpAddr> for NodeIp {
    #[inline]
    fn from(value: std::net::IpAddr) -> Self {
        Self(match value {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            std::net::IpAddr::V6(i) => i,
        })
    }
}

impl From<std::net::Ipv4Addr> for NodeIp {
    #[inline]
    fn from(value: std::net::Ipv4Addr) -> Self {
        Self(value.to_ipv6_mapped())
    }
}

impl From<std::net::Ipv6Addr> for NodeIp {
    #[inline]
    fn from(value: std::net::Ipv6Addr) -> Self {
        Self(value)
    }
}

impl From<NodeIp> for std::net::IpAddr {
    #[inline]
    fn from(value: NodeIp) -> Self {
        if let Some(ipv4) = value.0.to_ipv4_mapped() {
            ipv4.into()
        } else {
            value.0.into()
        }
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    //bincode::Encode,
    //bincode::Decode,
    serde::Serialize,
)]
pub struct NodeAddress {
    pub ip: NodeIp,
    pub port: u16,
}

impl fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.ip, self.port)
    }
}

impl std::str::FromStr for NodeAddress {
    type Err = eyre::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((ip, port)) = s.split_once('-') else {
            eyre::bail!("no '-' delimiter");
        };

        let ip: std::net::Ipv6Addr = ip.parse()?;
        let port: u16 = port.parse()?;

        Ok(Self {
            ip: NodeIp(ip),
            port,
        })
    }
}

impl From<(NodeIp, u16)> for NodeAddress {
    fn from(value: (NodeIp, u16)) -> Self {
        Self {
            ip: value.0,
            port: value.1,
        }
    }
}

#[derive(Debug)]
pub struct UnknownIp {
    pub err: std::io::Error,
    pub op: &'static str,
}

impl std::error::Error for UnknownIp {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.err)
    }
}

impl fmt::Display for UnknownIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to obtain local IP, operation '{}' failed: {}",
            self.op, self.err
        )
    }
}
