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
use std::collections::HashMap;

// SENDER_ENDPOINT is because we need a name for the sender config
const SENDER_ENDPOINT: &str = "address";

/// Config is the configuration for either a sender or a receiver
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub local: Local,
    #[serde(flatten)]
    pub connections: ConnectionConfig,
}

impl Config {
    /// get_endpoints get a list of all endpoints as a HashMap. For a Sender,
    /// the key is "address", for the Receiver the key is the name provided.
    pub fn get_endpoints(&self) -> HashMap<String, SocketAddr> {
        return match &self.connections {
            ConnectionConfig::Sender {
                address,
                connection_id: _,
            } => {
                let mut map: HashMap<String, SocketAddr> = HashMap::new();
                map.insert(String::from(SENDER_ENDPOINT), *address);
                return map;
            }
            ConnectionConfig::Receiver { endpoints } => {
                endpoints.iter().fold(HashMap::new(), |mut m, entrypoint| {
                    m.insert(entrypoint.name.clone(), entrypoint.address);
                    return m;
                })
            }
        };
    }
}

/// Local is the local host configuration options
#[derive(Debug, Deserialize, Serialize)]
pub struct Local {
    pub port: u16,
}

/// ConnectionConfig is the configuration for either a sender or receivers
#[derive(Debug, Deserialize, Serialize)]
pub enum ConnectionConfig {
    /// SenderConfig is the configuration for the sender, such as when sitting behind a game client.
    #[serde(rename = "sender_config")]
    Sender {
        address: SocketAddr,
        connection_id: String,
    },

    /// Receiver is the configuration for a recievers, such as a proxy that sits in front of a
    /// set of Dedicated Game Servers.    
    #[serde(rename = "receiver_config")]
    Receiver { endpoints: Vec<EndPoint> },
}

/// A singular endpoint, to pass on UDP packets to.
#[derive(Debug, Deserialize, Serialize, PartialEq)]
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
    use crate::config::{from_reader, Config, ConnectionConfig, EndPoint, Local, SENDER_ENDPOINT};
    use std::collections::HashMap;

    #[test]
    fn deserialise_sender() {
        let config = Config {
            local: Local { port: 7000 },
            connections: ConnectionConfig::Sender {
                address: "127.0.0.1:25999".parse().unwrap(),
                connection_id: String::from("1234"),
            },
        };
        let yaml = serde_yaml::to_string(&config).unwrap();
        println!("{}", yaml);
    }

    #[test]
    fn deserialise_receiver() {
        let config = Config {
            local: Local { port: 7000 },
            connections: ConnectionConfig::Receiver {
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
    fn parse_sender() {
        let yaml = "
local:
  port: 7000
sender_config:
  address: 127.0.0.1:25999
  connection_id: 1x7ijy6";
        let config = from_reader(yaml.as_bytes()).unwrap();
        assert_eq!(7000, config.local.port);
        match config.connections {
            ConnectionConfig::Sender {
                address,
                connection_id,
            } => {
                assert_eq!("1x7ijy6", connection_id);
                assert_eq!("127.0.0.1:25999", address.to_string())
            }
            ConnectionConfig::Receiver { .. } => panic!("Should not be a receiver"),
        }
    }

    #[test]
    fn parse_receiver() {
        let yaml = "
---
local:
  port: 7000
receiver_config:
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
        match config.connections {
            ConnectionConfig::Sender { .. } => panic!("Should not be a sender"),
            ConnectionConfig::Receiver { endpoints } => {
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
    fn get_endpoints_sender() {
        let expected_addr = "127.0.0.1:8080".parse().unwrap();
        let config = Config {
            local: Local { port: 0 },
            connections: ConnectionConfig::Sender {
                address: expected_addr,
                connection_id: "".to_string(),
            },
        };

        let mut expected = HashMap::new();
        expected.insert(String::from(SENDER_ENDPOINT), expected_addr);
        assert_eq!(expected, config.get_endpoints());
    }

    #[test]
    fn get_endpoints_receiver() {
        let yaml = "
---
local:
  port: 7000
receiver_config:
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
        let mut expected = HashMap::new();
        expected.insert(
            String::from("Game Server No. 1"),
            "127.0.0.1:26000".parse().unwrap(),
        );
        expected.insert(
            String::from("Game Server No. 2"),
            "127.0.0.1:26001".parse().unwrap(),
        );

        assert_eq!(expected, config.get_endpoints());
    }
}
