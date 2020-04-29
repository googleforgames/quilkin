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
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use serde_yaml::Error;

// CLIENT_ENDPOINT is because we need a name for the client endpoint configuration
const CLIENT_ENDPOINT: &str = "address";

/// Config is the configuration for either a Client or Server proxy
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub local: Local,
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(flatten)]
    pub connections: ConnectionConfig,
}

impl Config {
    /// get_endpoints get a list of all endpoints as a HashMap. For a Client proxy,
    /// the key is "address", for a Server proxy the key is the name provided.
    pub fn get_endpoints(&self) -> Vec<EndPoint> {
        return match &self.connections {
            ConnectionConfig::Client {
                address,
                connection_id: _,
            } => vec![EndPoint {
                name: String::from(CLIENT_ENDPOINT),
                address: *address,
                connection_ids: vec![],
            }],
            ConnectionConfig::Server { endpoints } => endpoints.clone(),
        };
    }
}

/// Local is the local host configuration options
#[derive(Debug, Deserialize, Serialize)]
pub struct Local {
    pub port: u16,
}

/// Filter is the configuration for a single filter
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Filter {
    pub name: String,
    pub config: serde_yaml::Value,
}

/// ConnectionConfig is the configuration for either a Client or Server proxy
#[derive(Debug, Deserialize, Serialize)]
pub enum ConnectionConfig {
    /// Client is the configuration for a client proxy, for sitting behind a game client.
    #[serde(rename = "client")]
    Client {
        address: SocketAddr,
        connection_id: String,
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
    pub connection_ids: Vec<String>,
}

/// from_reader returns a config from a given Reader
pub fn from_reader<R: io::Read>(input: R) -> Result<Config, Error> {
    let config: Config = serde_yaml::from_reader(input)?;
    return Ok(config);
}

#[cfg(test)]
mod tests {
    use serde_yaml::Value;

    use crate::config::{from_reader, Config, ConnectionConfig, EndPoint, Local, CLIENT_ENDPOINT};

    #[test]
    fn deserialise_client() {
        let config = Config {
            local: Local { port: 7000 },
            filters: vec![],
            connections: ConnectionConfig::Client {
                address: "127.0.0.1:25999".parse().unwrap(),
                connection_id: String::from("1234"),
            },
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        println!("{}", yaml);
    }

    #[test]
    fn deserialise_server() {
        let config = Config {
            local: Local { port: 7000 },
            filters: vec![],
            connections: ConnectionConfig::Server {
                endpoints: vec![
                    EndPoint {
                        name: String::from("No.1"),
                        address: "127.0.0.1:26000".parse().unwrap(),
                        connection_ids: vec![String::from("1234"), String::from("5678")],
                    },
                    EndPoint {
                        name: String::from("No.2"),
                        address: "127.0.0.1:26001".parse().unwrap(),
                        connection_ids: vec![String::from("1234")],
                    },
                ],
            },
        };
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
  address: 127.0.0.1:7001
  connection_id: 1x7ijy6
        ";
        let config = from_reader(yaml.as_bytes()).unwrap();

        let filter = config.filters.get(0).unwrap();
        assert_eq!("quilkin.core.v1.rate-limiter", filter.name);
        let filter_config = filter.config.as_mapping().unwrap();

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
  address: 127.0.0.1:25999
  connection_id: 1x7ijy6";
        let config = from_reader(yaml.as_bytes()).unwrap();
        assert_eq!(7000, config.local.port);
        match config.connections {
            ConnectionConfig::Client {
                address,
                connection_id,
            } => {
                assert_eq!("1x7ijy6", connection_id);
                assert_eq!("127.0.0.1:25999", address.to_string())
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
        - 1x7ijy6
        - 8gj3v2i
    - name: Game Server No. 2
      address: 127.0.0.1:26001
      connection_ids:
        - nkuy70x";
        let config = from_reader(yaml.as_bytes()).unwrap();
        assert_eq!(7000, config.local.port);
        assert_eq!(0, config.filters.len());
        match config.connections {
            ConnectionConfig::Client { .. } => panic!("Should not be a Client"),
            ConnectionConfig::Server { endpoints } => {
                let expected = vec![
                    EndPoint {
                        name: String::from("Game Server No. 1"),
                        address: "127.0.0.1:26000".parse().unwrap(),
                        connection_ids: vec![String::from("1x7ijy6"), String::from("8gj3v2i")],
                    },
                    EndPoint {
                        name: String::from("Game Server No. 2"),
                        address: "127.0.0.1:26001".parse().unwrap(),
                        connection_ids: vec![String::from("nkuy70x")],
                    },
                ];
                assert_eq!(expected, endpoints);
            }
        }
    }

    #[test]
    fn get_endpoints_client() {
        let expected_addr = "127.0.0.1:8080".parse().unwrap();
        let config = Config {
            filters: vec![],
            local: Local { port: 0 },
            connections: ConnectionConfig::Client {
                address: expected_addr,
                connection_id: "".to_string(),
            },
        };

        let expected = vec![EndPoint {
            name: String::from(CLIENT_ENDPOINT),
            address: expected_addr,
            connection_ids: vec![],
        }];
        assert_eq!(expected, config.get_endpoints());
    }

    #[test]
    fn get_endpoints_server() {
        let yaml = "
---
local:
  port: 7000
server:
  endpoints:
    - name: Game Server No. 1
      address: 127.0.0.1:26000
      connection_ids:
        - 1x7ijy6
        - 8gj3v2i
    - name: Game Server No. 2
      address: 127.0.0.1:26001
      connection_ids:
        - nkuy70x";
        let config = from_reader(yaml.as_bytes()).unwrap();

        let expected = vec![
            EndPoint {
                name: String::from("Game Server No. 1"),
                address: "127.0.0.1:26000".parse().unwrap(),
                connection_ids: vec!["1x7ijy6".to_string(), "8gj3v2i".to_string()],
            },
            EndPoint {
                name: String::from("Game Server No. 2"),
                address: "127.0.0.1:26001".parse().unwrap(),
                connection_ids: vec!["nkuy70x".to_string()],
            },
        ];

        assert_eq!(expected, config.get_endpoints());
    }
}
