/*
 * Copyright 2020 Google LLC
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

//! Quilkin configuration.

use std::{net::SocketAddr, sync::Arc};

use arc_swap::ArcSwap;
use base64_serde::base64_serde_type;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod builder;
mod config_type;
mod error;

use crate::endpoint::Endpoint;

pub use self::{builder::Builder, config_type::ConfigType, error::ValidationError};

base64_serde_type!(Base64Standard, base64::STANDARD);

// For some log messages on the hot path (potentially per-packet), we log 1 out
// of every `LOG_SAMPLING_RATE` occurrences to avoid spamming the logs.
pub(crate) const LOG_SAMPLING_RATE: u64 = 1000;

/// Config is the configuration of a proxy
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    #[serde(default)]
    pub admin: Option<Admin>,
    #[serde(default)]
    pub endpoints: Arc<ArcSwap<Vec<Endpoint>>>,
    #[serde(default)]
    pub filters: Arc<ArcSwap<Vec<Filter>>>,
    #[serde(default)]
    pub management_servers: Arc<ArcSwap<Vec<ManagementServer>>>,
    #[serde(default)]
    pub proxy: Proxy,
    pub version: Version,
}

impl Config {
    /// Returns a new empty [`Builder`] for [`Config`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Attempts to deserialize `input` as a YAML object representing `Self`.
    pub fn from_reader<R: std::io::Read>(input: R) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_reader(input)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Version {
    #[serde(rename = "v1alpha1")]
    V1Alpha1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    #[serde(default = "default_proxy_id")]
    pub id: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    #[serde(default = "default_upstream_address")]
    pub upstream_address: SocketAddr,
}

#[cfg(not(target_os = "linux"))]
fn default_proxy_id() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

#[cfg(target_os = "linux")]
fn default_proxy_id() -> String {
    sys_info::hostname().unwrap_or_else(|_| Uuid::new_v4().to_hyphenated().to_string())
}

fn default_proxy_port() -> u16 {
    7000
}

fn default_upstream_address() -> SocketAddr {
    (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            id: default_proxy_id(),
            port: default_proxy_port(),
            upstream_address: default_upstream_address(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Admin {
    pub address: SocketAddr,
}

impl Default for Admin {
    fn default() -> Self {
        Admin {
            address: (std::net::Ipv4Addr::UNSPECIFIED, 9091).into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagementServer {
    pub address: String,
}

/// Filter is the configuration for a single filter
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub name: String,
    pub config: Option<serde_json::Value>,
}

impl TryFrom<crate::xds::config::listener::v3::Filter> for Filter {
    type Error = eyre::Error;

    fn try_from(filter: crate::xds::config::listener::v3::Filter) -> Result<Self, Self::Error> {
        use crate::xds::config::listener::v3::filter::ConfigType;

        let config = if let Some(config_type) = filter.config_type {
            let config = match config_type {
                ConfigType::TypedConfig(any) => any,
                ConfigType::ConfigDiscovery(_) => {
                    return Err(eyre::eyre!("Config discovery is not supported."))
                }
            };
            Some(
                crate::filters::FilterRegistry::get_factory(&filter.name)
                    .ok_or_else(|| eyre::eyre!("Missing filter"))?
                    .encode_config_to_json(config)?,
            )
        } else {
            None
        };

        Ok(Self {
            name: filter.name,
            config,
        })
    }
}

impl TryFrom<Filter> for crate::xds::config::listener::v3::Filter {
    type Error = eyre::Error;

    fn try_from(filter: Filter) -> Result<Self, Self::Error> {
        use crate::xds::config::listener::v3::filter::ConfigType;

        let config = if let Some(config) = filter.config {
            Some(
                crate::filters::FilterRegistry::get_factory(&filter.name)
                    .ok_or_else(|| eyre::eyre!("Missing filter"))?
                    .encode_config_to_protobuf(config)?,
            )
        } else {
            None
        };

        Ok(Self {
            name: filter.name,
            config_type: config.map(ConfigType::TypedConfig),
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{endpoint::Metadata, filters::StaticFilter};

    fn parse_config(yaml: &str) -> Config {
        Config::from_reader(yaml.as_bytes()).unwrap()
    }

    #[test]
    fn deserialise_client() {
        let config = Builder::default()
            .port(7000)
            .endpoints(vec![Endpoint::new("127.0.0.1:25999".parse().unwrap())])
            .build()
            .unwrap();
        let _ = serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn deserialise_server() {
        let config = Builder::default()
            .port(7000)
            .upstream_address((std::net::Ipv4Addr::LOCALHOST, 43164).into())
            .endpoints(vec![
                Endpoint::new("127.0.0.1:26000".parse().unwrap()),
                Endpoint::new("127.0.0.1:26001".parse().unwrap()),
            ])
            .build()
            .unwrap();
        let _ = serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn parse_default_values() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "endpoints": [{
                "address": "127.0.0.1:25999",
            }],
        }))
        .unwrap();

        assert_eq!(config.proxy.port, 7000);
        assert_eq!(
            config.proxy.upstream_address,
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        );
        assert!(config.proxy.id.len() > 1);
    }

    #[test]
    fn parse_filter_config() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "proxy": {
                "id": "client-proxy",
                "port": 7000 // the port to receive traffic to locally
            },
            "endpoints": [{
                "address": "127.0.0.1:7001",
            }],
            "filters": [{
                "name": crate::filters::LocalRateLimit::NAME,
                "config": {
                    "map": "of arbitrary key value pairs",
                    "could": [
                        "also",
                        "be",
                        27u8,
                        true,
                    ],
                }
            }],
        }))
        .unwrap();

        let filter = config.filters.load().get(0).cloned().unwrap();
        assert_eq!(crate::filters::LocalRateLimit::NAME, filter.name);
        let filter_config = filter.config.as_ref().unwrap();
        assert_eq!(
            "of arbitrary key value pairs",
            filter_config.get("map").unwrap()
        );

        let could = filter_config.get("could").unwrap().as_array().unwrap();
        assert_eq!("also", could.get(0).unwrap().as_str().unwrap());
        assert_eq!("be", could.get(1).unwrap().as_str().unwrap());
        assert_eq!(27, could.get(2).unwrap().as_i64().unwrap());
        assert!(could.get(3).unwrap().as_bool().unwrap());
    }

    #[test]
    fn parse_proxy() {
        let yaml = "
version: v1alpha1
proxy:
  id: server-proxy
  port: 7000
  upstream_address: 127.0.0.1:43164
endpoints:
  - address: 127.0.0.1:25999
  ";
        let config = parse_config(yaml);

        assert_eq!(config.proxy.port, 7000);
        assert_eq!(config.proxy.id.as_str(), "server-proxy");
        assert_eq!(
            config.proxy.upstream_address,
            (std::net::Ipv4Addr::LOCALHOST, 43164).into()
        );
    }

    #[test]
    fn parse_client() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "endpoints": [{
                "address": "127.0.0.1:25999"
            }]
        }))
        .unwrap();

        assert_eq!(
            **config.endpoints.load(),
            vec![Endpoint::new((std::net::Ipv4Addr::LOCALHOST, 25999).into())],
        );
    }

    #[test]
    fn parse_server() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "endpoints": [
                {
                    "address": "127.0.0.1:26000",
                    "metadata": {
                        "quilkin.dev": {
                            "tokens": ["MXg3aWp5Ng==", "OGdqM3YyaQ=="],
                        }
                    }
                },
                {
                    "address": "127.0.0.1:26001",
                    "metadata": {
                        "quilkin.dev": {
                            "tokens": ["bmt1eTcweA=="],
                        }
                    }
                },
            ]
        }))
        .unwrap();

        assert_eq!(
            **config.endpoints.load(),
            vec![
                Endpoint::with_metadata(
                    "127.0.0.1:26000".parse().unwrap(),
                    Metadata {
                        tokens: vec!["1x7ijy6", "8gj3v2i"]
                            .into_iter()
                            .map(From::from)
                            .collect(),
                    },
                ),
                Endpoint::with_metadata(
                    "127.0.0.1:26001".parse().unwrap(),
                    Metadata {
                        tokens: vec!["nkuy70x"].into_iter().map(From::from).collect(),
                    },
                ),
            ],
        );
    }

    #[test]
    fn parse_management_servers() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "filters": [{
                "name": crate::filters::LocalRateLimit::NAME,
                "config": {
                    "map": "of arbitrary key value pairs",
                    "could":[
                        "also",
                        "be",
                        27u8,
                        true,
                    ],
                }
            }],
            "management_servers": [
                { "address": "127.0.0.1:25999" },
                { "address": "127.0.0.1:30000" },
            ],
        }))
        .unwrap();

        assert_eq!(
            **config.management_servers.load(),
            vec![
                ManagementServer {
                    address: "127.0.0.1:25999".into(),
                },
                ManagementServer {
                    address: "127.0.0.1:30000".into(),
                },
            ],
        );
    }

    #[test]
    fn deny_unused_fields() {
        let configs = vec![
            "
version: v1alpha1
foo: bar
endpoints:
  - address: 127.0.0.1:7001
",
            "
# proxy
version: v1alpha1
proxy:
  foo: bar
  id: client-proxy
  port: 7000
endpoints:
  - address: 127.0.0.1:7001
",
            "
# admin
version: v1alpha1
admin:
    foo: bar
    address: 127.0.0.1:7001
",
            "
# static.endpoints
version: v1alpha1
endpoints:
  - address: 127.0.0.1:7001
    connection_ids:
    - Mxg3aWp5Ng==
",
            "
# static.filters
version: v1alpha1
filters:
  - name: quilkin.core.v1.rate-limiter
    foo: bar
",
            "
# dynamic.management_servers
version: v1alpha1
dynamic:
  management_servers:
    - address: 127.0.0.1:25999
      foo: bar
",
        ];

        for config in configs {
            let result = Config::from_reader(config.as_bytes());
            let error = result.unwrap_err();
            assert!(format!("{error:?}").contains("unknown field"));
        }
    }
}
