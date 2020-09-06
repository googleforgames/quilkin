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
use std::fmt;
use std::io;
use std::net::SocketAddr;

use base64_serde::base64_serde_type;
use serde::export::Formatter;
use serde::{Deserialize, Serialize};

base64_serde_type!(Base64Standard, base64::STANDARD);

/// Validation failure for a Config
#[derive(Debug, PartialEq)]
pub enum ValidationError {
    NotUnique(String),
    EmptyList(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::NotUnique(field) => write!(f, "field {} is not unique", field),
            ValidationError::EmptyList(field) => write!(f, "field {} cannot be empty", field),
        }
    }
}

/// Config is the configuration for either a Client or Server proxy
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub local: Local,
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(flatten)]
    pub connections: ConnectionConfig,
    pub node: Option<Node>,
    pub dynamic_resources: Option<DynamicResources>,
}

#[derive(Debug)]
pub struct ConfigBuilder {
    pub local: Local,
    pub filters: Vec<Filter>,
    pub connections: ConnectionConfig,
    pub node: Option<Node>,
    pub dynamic_resources: Option<DynamicResources>,
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
        connection_id: ConnectionId,
        lb_policy: Option<LoadBalancerPolicy>,
    },

    /// Server is the configuration for a Dedicated Game Server proxy
    #[serde(rename = "server")]
    Server { endpoints: Vec<EndPoint> },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Node {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum DynamicResources {
    #[serde(rename = "ads_config")]
    AdsConfig { server_uri: Vec<String> },
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
                connection_id: _,
                lb_policy: _,
            } => {
                if addresses.iter().collect::<HashSet<_>>().len() != addresses.len() {
                    return Err(ValidationError::NotUnique(
                        "connections.addresses".to_string(),
                    ));
                }
            }
        }

        if let Some(resources) = &self.dynamic_resources {
            let DynamicResources::AdsConfig { server_uri } = resources;
            if server_uri.is_empty() {
                return Err(ValidationError::EmptyList(
                    "dynamic_resources.ads_config.server_uri".into(),
                ));
            }
        }

        Ok(())
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        ConfigBuilder {
            local: Local { port: 0 },
            filters: vec![],
            connections: ConnectionConfig::Client {
                addresses: vec![],
                connection_id: "".into(),
                lb_policy: None,
            },
            node: None,
            dynamic_resources: None,
        }
    }
}

impl ConfigBuilder {
    pub fn with_local(self, local: Local) -> Self {
        ConfigBuilder { local, ..self }
    }

    pub fn with_filters(self, filters: Vec<Filter>) -> Self {
        ConfigBuilder { filters, ..self }
    }

    pub fn with_connections(self, connections: ConnectionConfig) -> Self {
        ConfigBuilder {
            connections,
            ..self
        }
    }

    pub fn with_node(self, node: Option<Node>) -> Self {
        ConfigBuilder { node, ..self }
    }

    pub fn with_dynamic_resources(self, dynamic_resources: Option<DynamicResources>) -> Self {
        ConfigBuilder {
            dynamic_resources,
            ..self
        }
    }

    pub fn build(self) -> Config {
        Config {
            local: self.local,
            filters: self.filters,
            connections: self.connections,
            node: self.node,
            dynamic_resources: self.dynamic_resources,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use serde_yaml::Value;

    use crate::config::{
        Config, ConfigBuilder, ConnectionConfig, ConnectionId, EndPoint, LoadBalancerPolicy, Local,
        ValidationError,
    };

    #[test]
    fn deserialise_client() {
        let config = ConfigBuilder::default()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Client {
                addresses: vec!["127.0.0.1:25999".parse().unwrap()],
                connection_id: "1234".into(),
                lb_policy: Some(LoadBalancerPolicy::RoundRobin),
            })
            .build();
        let yaml = serde_yaml::to_string(&config).unwrap();
        println!("{}", yaml);
    }

    #[test]
    fn deserialise_server() {
        let config = ConfigBuilder::default()
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
  connection_id: MXg3aWp5Ng== # 1x7ijy6
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
  connection_id: MXg3aWp5Ng== # 1x7ijy6
  lb_policy: ROUND_ROBIN
  ";
        let config = Config::from_reader(yaml.as_bytes()).unwrap();
        assert_eq!(7000, config.local.port);
        match config.connections {
            ConnectionConfig::Client {
                addresses,
                connection_id,
                lb_policy,
            } => {
                assert_eq!(ConnectionId::from("1x7ijy6"), connection_id);
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
        let config = ConfigBuilder::default()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Client {
                addresses: vec![
                    "127.0.0.1:25999".parse().unwrap(),
                    "127.0.0.1:25998".parse().unwrap(),
                ],
                connection_id: "1234".into(),
                lb_policy: Some(LoadBalancerPolicy::RoundRobin),
            })
            .build();

        assert!(config.validate().is_ok());

        // client - non unique address
        let config = ConfigBuilder::default()
            .with_local(Local { port: 7000 })
            .with_connections(ConnectionConfig::Client {
                addresses: vec![
                    "127.0.0.1:25999".parse().unwrap(),
                    "127.0.0.1:25999".parse().unwrap(),
                ],
                connection_id: "1234".into(),
                lb_policy: Some(LoadBalancerPolicy::RoundRobin),
            })
            .build();

        assert_eq!(
            ValidationError::NotUnique("connections.addresses".to_string()).to_string(),
            config.validate().unwrap_err().to_string()
        );

        // server - valid
        let config = ConfigBuilder::default()
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
        let config = ConfigBuilder::default()
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
        let config = ConfigBuilder::default()
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
