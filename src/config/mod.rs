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

use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;

use base64_serde::base64_serde_type;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod builder;
mod endpoints;
mod error;
mod metadata;

pub use crate::config::endpoints::{
    EmptyListError, Endpoints, UpstreamEndpoints, UpstreamEndpointsIter,
};
pub(crate) use crate::config::error::ValueInvalidArgs;
pub use builder::Builder;
pub use error::ValidationError;
pub(crate) use metadata::{extract_endpoint_tokens, parse_endpoint_metadata_from_yaml};

base64_serde_type!(Base64Standard, base64::STANDARD);

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Version {
    #[serde(rename = "v1alpha1")]
    V1Alpha1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Proxy {
    #[serde(default = "default_proxy_id")]
    pub id: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
}

fn default_proxy_id() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

fn default_proxy_port() -> u16 {
    7000
}

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            id: default_proxy_id(),
            port: default_proxy_port(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminAddress {
    port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Admin {
    address: Option<AdminAddress>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ManagementServer {
    pub address: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Source {
    #[serde(rename = "static")]
    Static {
        #[serde(default)]
        filters: Vec<Filter>,

        endpoints: Vec<EndPoint>,
    },
    #[serde(rename = "dynamic")]
    Dynamic {
        management_servers: Vec<ManagementServer>,
    },
}

/// Config is the configuration for either a Client or Server proxy
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub version: Version,

    #[serde(default)]
    pub proxy: Proxy,

    pub admin: Option<Admin>,

    #[serde(flatten)]
    pub source: Source,

    // Limit struct creation to the builder. We use an Optional<Phantom>
    // so that we can create instances though deserialization.
    #[serde(skip_serializing)]
    pub(super) phantom: Option<PhantomData<()>>,
}

impl Source {
    /// Returns the list of filters if the config is a static config and None otherwise.
    /// This is a convenience function and should only be used for doc tests and tests.
    pub fn get_static_filters(&self) -> Option<&[Filter]> {
        match self {
            Source::Static {
                filters,
                endpoints: _,
            } => Some(filters),
            Source::Dynamic {
                management_servers: _,
            } => None,
        }
    }
}

/// Filter is the configuration for a single filter
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Filter {
    pub name: String,
    pub config: Option<serde_yaml::Value>,
}

/// A singular endpoint, to pass on UDP packets to.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct EndPoint {
    pub address: SocketAddr,
    pub metadata: Option<serde_yaml::Value>,
}

impl EndPoint {
    pub fn new(address: SocketAddr) -> Self {
        EndPoint::with_metadata(address, None)
    }

    pub fn with_metadata(address: SocketAddr, metadata: Option<serde_yaml::Value>) -> Self {
        EndPoint { address, metadata }
    }
}

impl Config {
    /// from_reader returns a config from a given Reader
    pub fn from_reader<R: io::Read>(input: R) -> Result<Config, serde_yaml::Error> {
        serde_yaml::from_reader(input)
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::Value;

    use crate::config::{Builder, Config, EndPoint, ManagementServer, Source};
    use std::collections::HashMap;

    fn parse_config(yaml: &str) -> Config {
        Config::from_reader(yaml.as_bytes()).unwrap()
    }

    fn assert_static_endpoints(source: &Source, expected_endpoints: Vec<EndPoint>) {
        match source {
            Source::Static {
                filters: _,
                endpoints,
            } => {
                assert_eq!(&expected_endpoints, endpoints,);
            }
            _ => unreachable!("expected static config source"),
        }
    }

    fn assert_management_servers(source: &Source, expected: Vec<ManagementServer>) {
        match source {
            Source::Dynamic { management_servers } => {
                assert_eq!(&expected, management_servers,);
            }
            _ => unreachable!("expected dynamic config source"),
        }
    }

    #[test]
    fn deserialise_client() {
        let config = Builder::empty()
            .with_port(7000)
            .with_static(
                vec![],
                vec![EndPoint::new("127.0.0.1:25999".parse().unwrap())],
            )
            .build();
        let _ = serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn deserialise_server() {
        let config = Builder::empty()
            .with_port(7000)
            .with_static(
                vec![],
                vec![
                    EndPoint::new("127.0.0.1:26000".parse().unwrap()),
                    EndPoint::new("127.0.0.1:26001".parse().unwrap()),
                ],
            )
            .build();
        let _ = serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn parse_default_values() {
        let yaml = "
version: v1alpha1
static:
  endpoints:
    - address: 127.0.0.1:25999
  ";
        let config = parse_config(yaml);

        assert_eq!(config.proxy.port, 7000);
        assert_eq!(config.proxy.id.len(), 36);
    }

    #[test]
    fn parse_filter_config() {
        let yaml = "
version: v1alpha1
proxy:
  id: client-proxy
  port: 7000 # the port to receive traffic to locally
static:
  filters: # new filters section
    - name: quilkin.core.v1.rate-limiter
      config:
        map: of arbitrary key value pairs
        could:
          - also
          - be
          - 27
          - true
  endpoints:
    - address: 127.0.0.1:7001
        ";
        let config = parse_config(yaml);

        let filter = config.source.get_static_filters().unwrap().get(0).unwrap();
        assert_eq!("quilkin.core.v1.rate-limiter", filter.name);
        let config = filter.config.as_ref().unwrap();
        let filter_config = config.as_mapping().unwrap();

        let key = Value::from("map");
        assert_eq!(
            "of arbitrary key value pairs",
            filter_config.get(&key).unwrap().as_str().unwrap()
        );

        let key = Value::from("could");
        let could = filter_config.get(&key).unwrap().as_sequence().unwrap();
        assert_eq!("also", could.get(0).unwrap().as_str().unwrap());
        assert_eq!("be", could.get(1).unwrap().as_str().unwrap());
        assert_eq!(27, could.get(2).unwrap().as_i64().unwrap());
        assert_eq!(true, could.get(3).unwrap().as_bool().unwrap());
    }

    #[test]
    fn parse_proxy() {
        let yaml = "
version: v1alpha1
proxy:
  id: server-proxy
  port: 7000
static:
  endpoints:
    - address: 127.0.0.1:25999
  ";
        let config = parse_config(yaml);

        assert_eq!(config.proxy.port, 7000);
        assert_eq!(config.proxy.id.as_str(), "server-proxy");
    }

    #[test]
    fn parse_client() {
        let yaml = "
version: v1alpha1
static:
  endpoints:
    - name: ep-1
      address: 127.0.0.1:25999
  ";
        let config = parse_config(yaml);

        assert_static_endpoints(
            &config.source,
            vec![EndPoint::new("127.0.0.1:25999".parse().unwrap())],
        );
    }

    #[test]
    fn parse_server() {
        let yaml = "
---
version: v1alpha1
static:
  endpoints:
    - address: 127.0.0.1:26000
      metadata:
        quilkin.dev:
          tokens:
            - MXg3aWp5Ng== #1x7ijy6
            - OGdqM3YyaQ== #8gj3v2i
    - address: 127.0.0.1:26001
      metadata:
        quilkin.dev:
          tokens:
            - bmt1eTcweA== #nkuy70x";
        let config = parse_config(yaml);
        assert_static_endpoints(
            &config.source,
            vec![
                EndPoint::with_metadata(
                    "127.0.0.1:26000".parse().unwrap(),
                    Some(
                        serde_yaml::to_value(
                            vec![(
                                "quilkin.dev",
                                vec![("tokens", vec!["MXg3aWp5Ng==", "OGdqM3YyaQ=="])]
                                    .into_iter()
                                    .collect::<HashMap<_, _>>(),
                            )]
                            .into_iter()
                            .collect::<HashMap<_, _>>(),
                        )
                        .unwrap(),
                    ),
                ),
                EndPoint::with_metadata(
                    "127.0.0.1:26001".parse().unwrap(),
                    Some(
                        serde_yaml::to_value(
                            vec![(
                                "quilkin.dev",
                                vec![("tokens", vec!["bmt1eTcweA=="])]
                                    .into_iter()
                                    .collect::<HashMap<_, _>>(),
                            )]
                            .into_iter()
                            .collect::<HashMap<_, _>>(),
                        )
                        .unwrap(),
                    ),
                ),
            ],
        );
    }

    #[test]
    fn parse_dynamic_source() {
        let yaml = "
version: v1alpha1
dynamic:
  filters:
    - name: quilkin.core.v1.rate-limiter
      config:
        map: of arbitrary key value pairs
        could:
          - also
          - be
          - 27
          - true
  management_servers:
    - address: 127.0.0.1:25999
    - address: 127.0.0.1:30000
  ";
        let config = parse_config(yaml);

        assert_management_servers(
            &config.source,
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
}
