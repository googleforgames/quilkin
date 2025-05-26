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

static mut IPV4: Option<std::net::Ipv4Addr> = None;
static mut IPV6: Option<std::net::Ipv6Addr> = None;

impl NodeIp {
    pub async fn configure_remote_host(remote_hostname: &str) -> eyre::Result<()> {
        static ONCE: std::sync::Once = std::sync::Once::new();

        if let Ok(ip) = remote_hostname.parse::<std::net::IpAddr>() {
            tracing::info!(%ip, "using IP instead of hostname");
            ONCE.call_once(|| {
                // SAFETY: this should be called early before `Self::local_ip` is ever called
                unsafe {
                    match ip {
                        std::net::IpAddr::V4(v4) => IPV4 = Some(v4),
                        std::net::IpAddr::V6(v6) => IPV6 = Some(v6),
                    }
                }
            });
            return Ok(());
        }

        let resolver = hickory_resolver::TokioResolver::builder_tokio()?.build();
        let lookup = resolver.lookup_ip(remote_hostname).await?;

        let mut ipv4 = None;
        let mut ipv6 = None;
        for ip in lookup {
            match ip {
                std::net::IpAddr::V4(v4) if ipv4.is_none() => {
                    ipv4 = Some(v4);
                }
                std::net::IpAddr::V6(v6) if ipv6.is_none() => {
                    ipv6 = Some(v6);
                }
                _ => {}
            }

            if ipv4.is_some() && ipv6.is_some() {
                break;
            }
        }

        eyre::ensure!(
            ipv4.is_some() || ipv6.is_some(),
            "no Ipv4 nor Ipv6 addresses were resolved"
        );

        ONCE.call_once(|| {
            // SAFETY: this should be called early before `Self::local_ip` is ever called
            unsafe {
                IPV4 = ipv4;
                IPV6 = ipv6;
            }
        });

        Ok(())
    }

    pub fn local_ip() -> Result<Self, UnknownIp> {
        fn ipv6() -> Option<std::net::IpAddr> {
            // SAFETY: this is not mutated at runtime
            let ipv6 = unsafe { IPV6? };
            let socket = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).ok()?;
            socket.connect((ipv6, 80)).ok()?;
            Some(socket.local_addr().ok()?.ip())
        }

        if let Some(ipv6) = ipv6() {
            return Ok(ipv6.into());
        }

        fn ipv4() -> Result<std::net::IpAddr, UnknownIp> {
            // SAFETY: this is not mutated at runtime
            let ipv4 = unsafe {
                IPV4.ok_or(UnknownIp {
                    err: std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "remote Ipv4 lookup address was not obtained",
                    ),
                    op: "resolve_remote",
                })?
            };
            let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
                .map_err(|err| UnknownIp { err, op: "bind" })?;
            socket
                .connect((ipv4, 80))
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

impl NodeAddress {
    #[inline]
    pub fn to_socket_addr(self) -> std::net::SocketAddr {
        self.ip.to_socket_addr(self.port)
    }
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
