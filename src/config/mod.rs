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
use tonic::transport::Endpoint as TonicEndpoint;
use uuid::Uuid;

mod builder;
mod endpoints;
mod error;

pub use crate::config::endpoints::{
    EmptyListError, Endpoints, UpstreamEndpoints, UpstreamEndpointsIter,
};
use crate::config::error::ValueInvalidArgs;
pub use builder::Builder;
pub use error::ValidationError;
use std::convert::TryInto;

base64_serde_type!(Base64Standard, base64::STANDARD);

#[derive(Debug, Deserialize, Serialize)]
pub enum Version {
    #[serde(rename = "v1alpha1")]
    V1Alpha1,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub enum ProxyMode {
    #[serde(rename = "CLIENT")]
    Client,
    #[serde(rename = "SERVER")]
    Server,
}

impl Default for ProxyMode {
    fn default() -> Self {
        ProxyMode::Server
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Proxy {
    #[serde(default)]
    pub mode: ProxyMode,
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
            mode: Default::default(),
            id: default_proxy_id(),
            port: default_proxy_port(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdminAddress {
    port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Admin {
    address: Option<AdminAddress>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ManagementServer {
    pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Source {
    #[serde(rename = "static")]
    Static {
        #[serde(default)]
        filters: Vec<Filter>,

        endpoints: Vec<EndPoint>,
    },
    #[serde(rename = "dynamic")]
    Dynamic {
        #[serde(default)]
        filters: Vec<Filter>,

        management_servers: Vec<ManagementServer>,
    },
}

/// Config is the configuration for either a Client or Server proxy
#[derive(Debug, Deserialize, Serialize)]
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
    pub fn get_filters(&self) -> &[Filter] {
        match self {
            Source::Static {
                filters,
                endpoints: _,
            } => filters,
            Source::Dynamic {
                filters,
                management_servers: _,
            } => filters,
        }
    }
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

impl AsRef<Vec<u8>> for ConnectionId {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

/// A singular endpoint, to pass on UDP packets to.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct EndPoint {
    pub name: String,
    pub address: SocketAddr,
    #[serde(default)]
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
        self.source.validate()?;

        Ok(())
    }
}

impl Source {
    /// Validates the source configuration.
    fn validate(&self) -> Result<(), ValidationError> {
        match &self {
            Source::Static {
                filters: _,
                endpoints,
            } => {
                if endpoints.is_empty() {
                    return Err(ValidationError::EmptyList("static.endpoints".to_string()));
                }

                if endpoints
                    .iter()
                    .map(|ep| ep.name.clone())
                    .collect::<HashSet<_>>()
                    .len()
                    != endpoints.len()
                {
                    return Err(ValidationError::NotUnique(
                        "static.endpoints.name".to_string(),
                    ));
                }

                if endpoints
                    .iter()
                    .map(|ep| ep.address)
                    .collect::<HashSet<_>>()
                    .len()
                    != endpoints.len()
                {
                    return Err(ValidationError::NotUnique(
                        "static.endpoints.address".to_string(),
                    ));
                }

                Ok(())
            }
            Source::Dynamic {
                filters: _,
                management_servers,
            } => {
                if management_servers.is_empty() {
                    return Err(ValidationError::EmptyList(
                        "dynamic.management_servers".to_string(),
                    ));
                }

                if management_servers
                    .iter()
                    .map(|server| &server.address)
                    .collect::<HashSet<_>>()
                    .len()
                    != management_servers.len()
                {
                    return Err(ValidationError::NotUnique(
                        "dynamic.management_servers.address".to_string(),
                    ));
                }

                for server in management_servers {
                    let res: Result<TonicEndpoint, _> = server.address.clone().try_into();
                    if res.is_err() {
                        return Err(ValidationError::ValueInvalid(ValueInvalidArgs {
                            field: "dynamic.management_servers.address".into(),
                            clarification: Some("the provided value must be a valid URI".into()),
                            examples: Some(vec![
                                "http://127.0.0.1:8080".into(),
                                "127.0.0.1:8081".into(),
                                "example.com".into(),
                            ]),
                        }));
                    }
                }

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::Value;

    use crate::config::{
        Builder, Config, EndPoint, ManagementServer, ProxyMode, Source, ValidationError,
    };

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
            Source::Dynamic {
                filters: _,
                management_servers,
            } => {
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
                vec![EndPoint {
                    name: "test".into(),
                    address: "127.0.0.1:25999".parse().unwrap(),
                    connection_ids: vec![],
                }],
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
    - name: ep-1
      address: 127.0.0.1:25999
  ";
        let config = parse_config(yaml);

        assert_eq!(config.proxy.mode, ProxyMode::Server);
        assert_eq!(config.proxy.port, 7000);
        assert_eq!(config.proxy.id.len(), 36);
    }

    #[test]
    fn parse_filter_config() {
        let yaml = "
version: v1alpha1
proxy:
  mode: CLIENT
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
    - name: endpoint-1
      address: 127.0.0.1:7001
        ";
        let config = parse_config(yaml);

        let filter = config.source.get_filters().get(0).unwrap();
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
  mode: CLIENT
  id: server-proxy
  port: 7000
static:
  endpoints:
    - name: ep-1
      address: 127.0.0.1:25999
  ";
        let config = parse_config(yaml);

        assert_eq!(config.proxy.mode, ProxyMode::Client);
        assert_eq!(config.proxy.port, 7000);
        assert_eq!(config.proxy.id.as_str(), "server-proxy");
    }

    #[test]
    fn parse_client() {
        let yaml = "
version: v1alpha1
proxy:
  mode: CLIENT
static:
  endpoints:
    - name: ep-1
      address: 127.0.0.1:25999
  ";
        let config = parse_config(yaml);

        assert_eq!(config.proxy.mode, ProxyMode::Client);
        assert_static_endpoints(
            &config.source,
            vec![EndPoint::new(
                "ep-1".into(),
                "127.0.0.1:25999".parse().unwrap(),
                vec![],
            )],
        );
    }

    #[test]
    fn parse_server() {
        let yaml = "
---
version: v1alpha1
proxy:
  mode: SERVER
static:
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
        let config = parse_config(yaml);
        assert_static_endpoints(
            &config.source,
            vec![
                EndPoint::new(
                    "Game Server No. 1".into(),
                    "127.0.0.1:26000".parse().unwrap(),
                    vec!["1x7ijy6".into(), "8gj3v2i".into()],
                ),
                EndPoint::new(
                    String::from("Game Server No. 2"),
                    "127.0.0.1:26001".parse().unwrap(),
                    vec!["nkuy70x".into()],
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

        let filter = config.source.get_filters().get(0).unwrap();
        assert_eq!("quilkin.core.v1.rate-limiter", filter.name);
        let filter_config = filter.config.as_ref().unwrap().as_mapping().unwrap();

        let key = Value::from("map");
        assert_eq!(
            "of arbitrary key value pairs",
            filter_config.get(&key).unwrap().as_str().unwrap()
        );

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

    #[test]
    fn validate_dynamic_source() {
        let yaml = "
# Valid management address list.
version: v1alpha1
dynamic:
  management_servers:
    - address: 127.0.0.1:25999
    - address: example.com
    - address: http://127.0.0.1:30000
  ";
        assert!(parse_config(yaml).validate().is_ok());

        let yaml = "
# Invalid management address.
version: v1alpha1
dynamic:
  management_servers:
    - address: 'not an endpoint address'
  ";
        match parse_config(yaml).validate().unwrap_err() {
            ValidationError::ValueInvalid(args) => {
                assert_eq!(args.field, "dynamic.management_servers.address".to_string());
            }
            err => unreachable!("expected invalid value error: got {}", err),
        }

        let yaml = "
# Duplicate management addresses.
version: v1alpha1
dynamic:
  management_servers:
    - address: 127.0.0.1:25999
    - address: 127.0.0.1:25999
  ";
        assert_eq!(
            ValidationError::NotUnique("dynamic.management_servers.address".to_string())
                .to_string(),
            parse_config(yaml).validate().unwrap_err().to_string()
        );
    }

    #[test]
    fn validate() {
        // client - valid
        let yaml = "
version: v1alpha1
static:
  endpoints:
    - name: a
      address: 127.0.0.1:25999
    - name: b
      address: 127.0.0.1:25998
";
        assert!(parse_config(yaml).validate().is_ok());

        let yaml = "
# Non unique addresses.
version: v1alpha1
static:
  endpoints:
    - name: a
      address: 127.0.0.1:25999
    - name: b
      address: 127.0.0.1:25999
";
        assert_eq!(
            ValidationError::NotUnique("static.endpoints.address".to_string()).to_string(),
            parse_config(yaml).validate().unwrap_err().to_string()
        );

        let yaml = "
# Empty endpoints list
version: v1alpha1
static:
  endpoints: []
";
        assert_eq!(
            ValidationError::EmptyList("static.endpoints".to_string()).to_string(),
            parse_config(yaml).validate().unwrap_err().to_string()
        );

        let yaml = "
# Non unique endpoint names.
version: v1alpha1
static:
  endpoints:
    - name: a
      address: 127.0.0.1:25998
    - name: a
      address: 127.0.0.1:25999
";
        assert_eq!(
            ValidationError::NotUnique("static.endpoints.name".to_string()).to_string(),
            parse_config(yaml).validate().unwrap_err().to_string()
        );
    }
}
