/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::{
    convert::{TryFrom, TryInto},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::{
    name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime},
    AsyncResolver,
};

use crate::xds::config::core::v3::{
    address::Address as EnvoyAddress, SocketAddress as EnvoySocketAddress,
};

/// A valid socket address. This differs from `std::net::SocketAddr`, in that it
/// it supports parsing Domain Names in addition to IP addresses. Domain Names
/// are resolved when `ToSocketAddrs::to_socket_addrs` is called.
#[derive(Debug, PartialEq, Clone, PartialOrd, Ord, Eq, Hash)]
pub struct EndpointAddress {
    /// A valid name or IP address that resolves to a address.
    pub host: AddressKind,
    /// The port of the socket address, if present.
    pub port: u16,
}

impl EndpointAddress {
    pub const UNSPECIFIED: Self = Self {
        host: AddressKind::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        port: 0,
    };
    pub const LOCALHOST: Self = Self {
        host: AddressKind::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: 0,
    };
}

impl EndpointAddress {
    /// Returns the port for the endpoint address, or `0` if no port
    /// was specified.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the socket address for the endpoint, resolving any DNS entries
    /// if present.
    pub async fn to_socket_addr(&self) -> std::io::Result<SocketAddr> {
        static DNS: Lazy<
            AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>,
        > = Lazy::new(|| AsyncResolver::tokio_from_system_conf().unwrap());

        let ip = match &self.host {
            AddressKind::Ip(ip) => *ip,
            AddressKind::Name(name) => {
                static CACHE: Lazy<crate::ttl_map::TtlMap<String, IpAddr>> =
                    Lazy::new(<_>::default);

                match CACHE.get(name) {
                    Some(ip) => **ip,
                    None => {
                        let set = DNS
                            .lookup_ip(&**name)
                            .await?
                            .iter()
                            .collect::<std::collections::HashSet<_>>();

                        let ip = set
                            .iter()
                            .find(|item| matches!(item, IpAddr::V6(_)))
                            .or_else(|| set.iter().find(|item| matches!(item, IpAddr::V4(_))))
                            .copied()
                            .ok_or_else(|| {
                                std::io::Error::new(
                                    std::io::ErrorKind::Other,
                                    "no ip address found",
                                )
                            })?;

                        CACHE.insert(name.clone(), ip);
                        ip
                    }
                }
            }
        };

        Ok(SocketAddr::from((ip, self.port)))
    }
}

/// Forwards the deserialisation to use [`std::net::ToSocketAddrs`] instead of
/// [`FromStr`] for validation which allows us to resolve DNS hostnames such as
/// `localhost` or container network names at parse-time.
impl FromStr for EndpointAddress {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let url = if input.starts_with("udp://") {
            url::Url::parse(input)?
        } else if input.contains("://") {
            return Err(ParseError::NonUdpScheme);
        } else {
            url::Url::parse(&format!("udp://{}", input))?
        };

        if !matches!(url.scheme(), "" | "udp") {
            return Err(ParseError::NonUdpScheme);
        }

        // Check if the URL has a path
        if !url.path().is_empty() && url.path() != "/" {
            return Err(ParseError::PathsNotAllowed);
        }

        let host = url
            .host_str()
            .map(String::from)
            .ok_or(ParseError::EmptyHost)?;
        // Infallible
        let host = host.parse::<AddressKind>().unwrap();
        let port = url.port().ok_or(ParseError::EmptyPort)?;

        Ok(Self { host, port })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("non UDP based URLs are not permitted")]
    NonUdpScheme,
    #[error("hostname is required")]
    EmptyHost,
    #[error("port is required")]
    EmptyPort,
    #[error("parser error: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("No paths allowed in URLs, it must include only the hostname and port")]
    PathsNotAllowed,
}

impl From<SocketAddr> for EndpointAddress {
    fn from(socket: SocketAddr) -> Self {
        Self {
            host: AddressKind::Ip(socket.ip()),
            port: socket.port(),
        }
    }
}

impl From<(IpAddr, u16)> for EndpointAddress {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        Self {
            host: AddressKind::Ip(ip),
            port,
        }
    }
}

impl From<(Ipv4Addr, u16)> for EndpointAddress {
    fn from((ip, port): (Ipv4Addr, u16)) -> Self {
        Self {
            host: AddressKind::Ip(IpAddr::V4(ip)),
            port,
        }
    }
}

impl From<([u8; 4], u16)> for EndpointAddress {
    fn from((ip, port): ([u8; 4], u16)) -> Self {
        Self {
            host: AddressKind::Ip(IpAddr::V4(ip.into())),
            port,
        }
    }
}

impl From<(Ipv6Addr, u16)> for EndpointAddress {
    fn from((ip, port): (Ipv6Addr, u16)) -> Self {
        Self {
            host: AddressKind::Ip(IpAddr::V6(ip)),
            port,
        }
    }
}

impl From<(String, u16)> for EndpointAddress {
    fn from((ip, port): (String, u16)) -> Self {
        Self {
            host: ip.parse().unwrap_or(AddressKind::Name(ip)),
            port,
        }
    }
}

impl From<EndpointAddress> for EnvoySocketAddress {
    fn from(address: EndpointAddress) -> Self {
        use crate::xds::config::core::v3::socket_address::{PortSpecifier, Protocol};

        Self {
            protocol: Protocol::Udp as i32,
            address: address.host.to_string(),
            port_specifier: Some(PortSpecifier::PortValue(u32::from(address.port))),
            ..<_>::default()
        }
    }
}

impl TryFrom<EnvoySocketAddress> for EndpointAddress {
    type Error = eyre::Error;

    fn try_from(value: EnvoySocketAddress) -> Result<Self, Self::Error> {
        use crate::xds::config::core::v3::socket_address::PortSpecifier;

        let address = Self {
            host: value.address.parse()?,
            port: match value.port_specifier {
                Some(PortSpecifier::PortValue(value)) => value.try_into()?,
                Some(PortSpecifier::NamedPort(_)) => {
                    return Err(eyre::eyre!("named ports are not supported"))
                }
                None => return Err(eyre::eyre!("ports are required")),
            },
        };

        Ok(address)
    }
}

impl From<EndpointAddress> for crate::xds::config::core::v3::Address {
    fn from(address: EndpointAddress) -> Self {
        Self {
            address: Some(address.into()),
        }
    }
}

impl From<EndpointAddress> for EnvoyAddress {
    fn from(address: EndpointAddress) -> Self {
        Self::SocketAddress(address.into())
    }
}

impl TryFrom<EnvoyAddress> for EndpointAddress {
    type Error = eyre::Error;

    fn try_from(value: EnvoyAddress) -> Result<Self, Self::Error> {
        match value {
            EnvoyAddress::SocketAddress(address) => address.try_into(),
            _ => Err(eyre::eyre!("Unsupported Envoy address type.")),
        }
    }
}

impl TryFrom<crate::xds::config::core::v3::Address> for EndpointAddress {
    type Error = eyre::Error;

    fn try_from(value: crate::xds::config::core::v3::Address) -> Result<Self, Self::Error> {
        match value.address {
            Some(address) => Self::try_from(address),
            _ => Err(eyre::eyre!("No address found")),
        }
    }
}

impl TryFrom<crate::xds::config::endpoint::v3::Endpoint> for EndpointAddress {
    type Error = eyre::Error;

    fn try_from(value: crate::xds::config::endpoint::v3::Endpoint) -> Result<Self, Self::Error> {
        match value.address {
            Some(address) => Self::try_from(address),
            _ => Err(eyre::eyre!("Missing address in endpoint")),
        }
    }
}

impl fmt::Display for EndpointAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl<'de> Deserialize<'de> for EndpointAddress {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept borrowed or owned strings.
        let string = <std::borrow::Cow<'de, str>>::deserialize(de)?;
        string.parse::<Self>().map_err(serde::de::Error::custom)
    }
}

/// The kind of address, such as Domain Name or IP address. **Note** that
/// the `FromStr` implementation doesn't actually validate that the name is
/// resolvable. Use [`EndpointAddress`] for complete address validation.
#[derive(Debug, PartialEq, Clone, PartialOrd, Eq, Hash, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AddressKind {
    Name(String),
    Ip(IpAddr),
}

impl FromStr for AddressKind {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.parse()
            .map(Self::Ip)
            .unwrap_or_else(|_| Self::Name(s.to_owned())))
    }
}

impl fmt::Display for AddressKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => name.fmt(f),
            Self::Ip(ip) => ip.fmt(f),
        }
    }
}

impl Serialize for EndpointAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
