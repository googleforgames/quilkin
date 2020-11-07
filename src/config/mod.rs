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

use std::collections::HashSet;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;

use base64_serde::base64_serde_type;
use serde::{Deserialize, Serialize};

mod builder;
mod error;

pub use builder::Builder;
pub use error::ValidationError;

base64_serde_type!(Base64Standard, base64::STANDARD);

// CLIENT_ENDPOINT_PREFIX is a prefix to the name of a client proxy's endpoint.
const CLIENT_ENDPOINT_PREFIX: &str = "address";

/// Config is the configuration for either a Client or Server proxy
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub local: Local,
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(flatten)]
    pub connections: ConnectionConfig,

    // Limit struct creation to the builder. We use an Optional<Phantom>
    // so that we can create instances though deserialization.
    pub(super) phantom: Option<PhantomData<()>>,
}

impl ConnectionConfig {
    pub fn get_endpoints(&self) -> Vec<EndPoint> {
        match self {
            ConnectionConfig::Client { addresses, .. } => addresses
                .iter()
                .cloned()
                .enumerate()
                .map(|(offset, address)| {
                    EndPoint::new(
                        format!("{}-{}", CLIENT_ENDPOINT_PREFIX, offset),
                        address,
                        vec![],
                    )
                })
                .collect(),
            ConnectionConfig::Server { endpoints } => endpoints.clone(),
        }
    }
}

/// Local is the local host configuration options
#[derive(Debug, Deserialize, Serialize)]
pub struct Local {
    pub port: u16,
}

/// LoadBalancerPolicy represents how a proxy load-balances
/// traffic between endpoints.
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum LoadBalancerPolicy {
    /// Send all traffic to all endpoints.
    #[serde(rename = "BROADCAST")]
    Broadcast,
    /// Send traffic to endpoints in turns.
    #[serde(rename = "ROUND_ROBIN")]
    RoundRobin,
    /// Send traffic to endpoints chosen at random.
    #[serde(rename = "RANDOM")]
    Random,
}

/// Filter is the configuration for a single filter
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Filter {
    pub name: String,
    pub config: Option<serde_yaml::Value>,
}

/// ConnectionId is the connection auth token value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionId(#[serde(with = "Base64Standard")] Vec<u8>);

impl From<&str> for ConnectionId {
    fn from(s: &str) -> Self {
        ConnectionId(s.as_bytes().to_vec())
    }
}

/// ConnectionConfig is the configuration for either a Client or Server proxy
#[derive(Debug, Deserialize, Serialize)]
pub enum ConnectionConfig {
    /// Client is the configuration for a client proxy, for sitting behind a game client.
    #[serde(rename = "client")]
    Client {
        addresses: Vec<SocketAddr>,
        lb_policy: Option<LoadBalancerPolicy>,
    },

    /// Server is the configuration for a Dedicated Game Server proxy
    #[serde(rename = "server")]
    Server { endpoints: Vec<EndPoint> },
}

/// A singular endpoint, to pass on UDP packets to.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct EndPoint {
    pub name: String,
    pub address: SocketAddr,
    pub connection_ids: Vec<ConnectionId>,
}

impl EndPoint {
    pub fn new(name: String, address: SocketAddr, connection_ids: Vec<ConnectionId>) -> Self {
        EndPoint {
            name,
            address,
            connection_ids,
        }
    }
}

impl Config {
    /// from_reader returns a config from a given Reader
    pub fn from_reader<R: io::Read>(input: R) -> Result<Config, serde_yaml::Error> {
        serde_yaml::from_reader(input)
    }

    /// validates the current Config.
    pub fn validate(&self) -> Result<(), ValidationError> {
        match &self.connections {
            ConnectionConfig::Server { endpoints } => {
                if endpoints
                    .iter()
                    .map(|ep| ep.name.clone())
                    .collect::<HashSet<_>>()
                    .len()
                    != endpoints.len()
                {
                    return Err(ValidationError::NotUnique("endpoint.name".to_string()));
                }

                if endpoints
                    .iter()
                    .map(|ep| ep.address)
                    .collect::<HashSet<_>>()
                    .len()
                    != endpoints.len()
                {
                    return Err(ValidationError::NotUnique("endpoint.address".to_string()));
                }
            }
            ConnectionConfig::Client {
                addresses,
                lb_policy: _,
            } => {
                if addresses.iter().collect::<HashSet<_>>().len() != addresses.len() {
                    return Err(ValidationError::NotUnique(
                        "connections.addresses".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use serde_yaml::Value;

    use crate::config::{
        Builder, Config, ConnectionConfig, EndPoint, LoadBalancerPolicy, Local, ValidationError,
    };

    #[test]
    fn deserialise_client() {
        let config = Builder::empty()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Client {
                addresses: vec!["127.0.0.1:25999".parse().unwrap()],
                lb_policy: Some(LoadBalancerPolicy::RoundRobin),
            })
            .build();
        let yaml = serde_yaml::to_string(&config).unwrap();
        println!("{}", yaml);
    }

    #[test]
    fn deserialise_server() {
        let config = Builder::empty()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Server {
                endpoints: vec![
                    EndPoint {
                        name: String::from("No.1"),
                        address: "127.0.0.1:26000".parse().unwrap(),
                        connection_ids: vec!["1234".into(), "5678".into()],
                    },
                    EndPoint {
                        name: String::from("No.2"),
                        address: "127.0.0.1:26001".parse().unwrap(),
                        connection_ids: vec!["1234".into()],
                    },
                ],
            })
            .build();
        let yaml = serde_yaml::to_string(&config).unwrap();
        println!("{}", yaml);
    }

    #[test]
    fn parse_filter_config() {
        let yaml = "
local:
  port: 7000 # the port to receive traffic to locally
filters: # new filters section
  - name: quilkin.core.v1.rate-limiter
    config:
      map: of arbitrary key value pairs
      could:
        - also
        - be
        - 27
        - true
client:
  addresses:
    - 127.0.0.1:7001
        ";
        let config = Config::from_reader(yaml.as_bytes()).unwrap();

        let filter = config.filters.get(0).unwrap();
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
    fn parse_client() {
        let yaml = "
local:
  port: 7000
client:
  addresses:
    - 127.0.0.1:25999
  lb_policy: ROUND_ROBIN
  ";
        let config = Config::from_reader(yaml.as_bytes()).unwrap();
        assert_eq!(7000, config.local.port);
        match config.connections {
            ConnectionConfig::Client {
                addresses,
                lb_policy,
            } => {
                assert_eq!(
                    vec!["127.0.0.1:25999".parse::<SocketAddr>().unwrap()],
                    addresses
                );
                assert_eq!(Some(LoadBalancerPolicy::RoundRobin), lb_policy);
            }
            ConnectionConfig::Server { .. } => panic!("Should not be a receiver"),
        }
    }

    #[test]
    fn parse_server() {
        let yaml = "
---
local:
  port: 7000
server:
  endpoints:
    - name: Game Server No. 1
      address: 127.0.0.1:26000
      connection_ids:
        - MXg3aWp5Ng== #1x7ijy6
        - OGdqM3YyaQ== #8gj3v2i
    - name: Game Server No. 2
      address: 127.0.0.1:26001
      connection_ids:
        - bmt1eTcweA== #nkuy70x";
        let config = Config::from_reader(yaml.as_bytes()).unwrap();
        assert_eq!(7000, config.local.port);
        assert_eq!(0, config.filters.len());
        match config.connections {
            ConnectionConfig::Client { .. } => panic!("Should not be a Client"),
            ConnectionConfig::Server { endpoints } => {
                let expected = vec![
                    EndPoint {
                        name: String::from("Game Server No. 1"),
                        address: "127.0.0.1:26000".parse().unwrap(),
                        connection_ids: vec!["1x7ijy6".into(), "8gj3v2i".into()],
                    },
                    EndPoint {
                        name: String::from("Game Server No. 2"),
                        address: "127.0.0.1:26001".parse().unwrap(),
                        connection_ids: vec!["nkuy70x".into()],
                    },
                ];
                assert_eq!(expected, endpoints);
            }
        }
    }

    #[test]
    fn validate() {
        // client - valid
        let config = Builder::empty()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Client {
                addresses: vec![
                    "127.0.0.1:25999".parse().unwrap(),
                    "127.0.0.1:25998".parse().unwrap(),
                ],
                lb_policy: Some(LoadBalancerPolicy::RoundRobin),
            })
            .build();

        assert!(config.validate().is_ok());

        // client - non unique address
        let config = Builder::empty()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Client {
                addresses: vec![
                    "127.0.0.1:25999".parse().unwrap(),
                    "127.0.0.1:25999".parse().unwrap(),
                ],
                lb_policy: Some(LoadBalancerPolicy::RoundRobin),
            })
            .build();

        assert_eq!(
            ValidationError::NotUnique("connections.addresses".to_string()).to_string(),
            config.validate().unwrap_err().to_string()
        );

        // server - valid
        let config = Builder::empty()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Server {
                endpoints: vec![
                    EndPoint {
                        name: String::from("ONE"),
                        address: "127.0.0.1:26000".parse().unwrap(),
                        connection_ids: vec!["1234".into(), "5678".into()],
                    },
                    EndPoint {
                        name: String::from("TWO"),
                        address: "127.0.0.1:26001".parse().unwrap(),
                        connection_ids: vec!["1234".into()],
                    },
                ],
            })
            .build();
        assert!(config.validate().is_ok());

        // server - non unique endpoint names
        let config = Builder::empty()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Server {
                endpoints: vec![
                    EndPoint {
                        name: String::from("SAME"),
                        address: "127.0.0.1:26000".parse().unwrap(),
                        connection_ids: vec!["1234".into(), "5678".into()],
                    },
                    EndPoint {
                        name: String::from("SAME"),
                        address: "127.0.0.1:26001".parse().unwrap(),
                        connection_ids: vec!["1234".into()],
                    },
                ],
            })
            .build();

        assert_eq!(
            ValidationError::NotUnique("endpoint.name".to_string()).to_string(),
            config.validate().unwrap_err().to_string()
        );

        // server - non unique addresses
        let config = Builder::empty()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Server {
                endpoints: vec![
                    EndPoint {
                        name: String::from("ONE"),
                        address: "127.0.0.1:26000".parse().unwrap(),
                        connection_ids: vec!["1234".into(), "5678".into()],
                    },
                    EndPoint {
                        name: String::from("TWO"),
                        address: "127.0.0.1:26000".parse().unwrap(),
                        connection_ids: vec!["1234".into()],
                    },
                ],
            })
            .build();

        assert_eq!(
            ValidationError::NotUnique("endpoint.address".to_string()).to_string(),
            config.validate().unwrap_err().to_string()
        );
    }
}
