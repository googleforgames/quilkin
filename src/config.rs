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

use std::net::SocketAddr;

use base64_serde::base64_serde_type;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod builder;
mod config_type;
mod error;

use crate::endpoint::{base64_set, Endpoint};

pub(crate) use self::error::ValueInvalidArgs;

pub use self::{builder::Builder, config_type::ConfigType, error::ValidationError};
use crate::capture_bytes::Strategy;
use std::collections::HashSet;

base64_serde_type!(Base64Standard, base64::STANDARD);

// For some log messages on the hot path (potentially per-packet), we log 1 out
// of every `LOG_SAMPLING_RATE` occurrences to avoid spamming the logs.
pub(crate) const LOG_SAMPLING_RATE: u64 = 1000;

/// Config is the configuration of a proxy
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    pub version: Version,

    #[serde(default)]
    pub proxy: Proxy,

    #[serde(default)]
    pub admin: Admin,

    #[serde(flatten)]
    pub source: Source,
}

impl Config {
    /// Attempts to locate and parse a `Config` located at either `path`, the
    /// `$QUILKIN_CONFIG` environment variable if set, the current directory,
    /// or the `/etc/quilkin` directory (on unix platforms only). Returns an
    /// error if the found configuration is invalid, or if no configuration
    /// could be found at any location.
    pub fn find(
        log: &slog::Logger,
        path: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        const ENV_CONFIG_PATH: &str = "QUILKIN_CONFIG";
        const CONFIG_FILE: &str = "quilkin.yaml";

        let config_env = std::env::var(ENV_CONFIG_PATH).ok();

        let config_path = std::path::Path::new(
            path.or_else(|| config_env.as_deref())
                .unwrap_or(CONFIG_FILE),
        )
        .canonicalize()?;

        slog::info!(log, "Found configuration file"; "path" => config_path.display());

        std::fs::File::open(&config_path)
            .or_else(|error| {
                if cfg!(unix) {
                    std::fs::File::open("/etc/quilkin/quilkin.yaml")
                } else {
                    Err(error)
                }
            })
            .map_err(From::from)
            .and_then(|file| Self::from_reader(file).map_err(From::from))
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

impl Default for Proxy {
    fn default() -> Self {
        Proxy {
            id: default_proxy_id(),
            port: default_proxy_port(),
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
            address: "[::]:9091".parse().unwrap(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagementServer {
    pub address: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Represents a filter chain that is associated with a set of packet versions.
/// The filter will be used to process only those packets that match any of its
/// associated versions.
pub struct VersionedStaticFilterChain {
    #[serde(with = "base64_set")]
    /// A list of packet versions that this filter chain will process packets for.
    /// Each version is provided as a Standard Base64 encoding with padding.
    pub versions: base64_set::Set,
    /// The list of filters that make up the filter chain.
    pub filters: Vec<Filter>,
}

/// default value for [`CaptureVersion::remove`].
fn default_capture_version_remove() -> bool {
    true
}

/// Configures how to collect version information from a packet.
///
/// The collected sequence of bytes and will matched
/// against the current versioned filter chains that the proxy is
/// running with.
///
/// If a match is found, the matching filter chain is used to process
/// the packet.
///
/// Note that once the version for the first packet in a session has been set,
/// all subsequent packets for that session must use the same version otherwise
/// they will be dropped.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaptureVersion {
    /// Strategy to use to capture the version.
    pub strategy: Strategy,
    /// Number of bytes to capture as the version.
    pub size: usize,
    #[serde(default = "default_capture_version_remove")]
    /// Whether or not to remove the remove bytes from the original packet
    /// after capture.
    pub remove: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum StaticFilterChainConfig {
    #[serde(rename = "versioned")]
    /// In versioned mode, version information is collected from each packet
    /// and matched against a set of filter chains. If a match is found, that
    /// filter chain is used to process the packet.
    Versioned {
        /// Configures how to capture the version from packets.
        capture_version: CaptureVersion,
        /// Set of filter chain configurations.
        filter_chains: Vec<VersionedStaticFilterChain>,
    },

    #[serde(rename = "filters")]
    /// In non-versioned mode, a single filter chain is used to process
    /// all packets.
    NonVersioned(#[serde(default)] Vec<Filter>),
}

impl Default for StaticFilterChainConfig {
    /// Default is an empty filter chain.
    fn default() -> Self {
        StaticFilterChainConfig::NonVersioned(vec![])
    }
}

/// Version configuration for filter chains that will be received
/// dynamically from a management server.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedDynamicFilterChainConfig {
    /// Configures how to capture the version from packets.
    pub capture_version: CaptureVersion,
}

/// Configuration for filter chains that will be received
/// dynamically from  a management server.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicFilterChainConfig {
    /// Enable versioned filter chains.
    pub versioned: VersionedDynamicFilterChainConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum Source {
    #[serde(rename = "static")]
    /// Configures Quilkin with fixed endpoint and filter values.
    /// These values do not change at runtime.
    Static {
        #[serde(default)]
        /// Filter chain configuration.
        filter_chain: StaticFilterChainConfig,
        /// List of upstream endpoint to forward packets to.
        endpoints: Vec<Endpoint>,
    },
    #[serde(rename = "dynamic")]
    /// Configures Quilkin to retrieve endpoint and filter values from
    /// a management server.
    /// This enables Quilkin to run with configuration that can be updated at runtime.
    Dynamic {
        /// Configures filter chains received from the management server.
        filter_chain: Option<DynamicFilterChainConfig>,
        /// Management server configuration.
        /// Multiple servers can be configured for redundancy -
        /// the proxy will retry establishing a connection in a round robin manner
        /// in case of errors.
        management_servers: Vec<ManagementServer>,
    },
}

impl Source {
    /// Returns the list of filters if the config contains a static, non versioned
    /// filter chain. It returns None otherwise.
    ///
    /// NOTE: This is a convenience function and should only be used for doc tests and tests.
    pub fn get_static_non_versioned_filters(&self) -> Option<&[Filter]> {
        match self {
            Source::Static {
                filter_chain,
                endpoints: _,
            } => match filter_chain {
                StaticFilterChainConfig::Versioned { .. } => None,
                StaticFilterChainConfig::NonVersioned(filters) => Some(filters),
            },
            Source::Dynamic {
                filter_chain: _,
                management_servers: _,
            } => None,
        }
    }

    /// Returns the list of filters if the config contains a static, versioned
    /// filter chain. It returns None otherwise.
    ///
    /// NOTE: This is a convenience function and should only be used for doc tests and tests.
    pub fn get_static_versioned_filters(&self) -> Option<&[VersionedStaticFilterChain]> {
        match self {
            Source::Static {
                filter_chain,
                endpoints: _,
            } => match filter_chain {
                StaticFilterChainConfig::NonVersioned(_) => None,
                StaticFilterChainConfig::Versioned {
                    capture_version: _,
                    filter_chains,
                } => Some(filter_chains),
            },
            Source::Dynamic {
                filter_chain: _,
                management_servers: _,
            } => None,
        }
    }

    /// Returns the [`CaptureVersion`] for the config if one was provided.
    ///
    /// NOTE: This is a convenience function and should only be used for doc tests and tests.
    pub fn get_capture_version(&self) -> Option<CaptureVersion> {
        match self {
            Source::Static {
                filter_chain,
                endpoints: _,
            } => match filter_chain {
                StaticFilterChainConfig::Versioned {
                    capture_version,
                    filter_chains: _,
                } => Some(capture_version.clone()),
                StaticFilterChainConfig::NonVersioned(_) => None,
            },
            Source::Dynamic {
                filter_chain,
                management_servers: _,
            } => filter_chain
                .as_ref()
                .map(|config| config.versioned.capture_version.clone()),
        }
    }
}

/// Filter is the configuration for a single filter
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub name: String,
    pub config: Option<serde_yaml::Value>,
}

/// Validates the filter chain version provided in a configuration.
pub(crate) struct ValidateFilterChainVersions<'a>(
    /// Set of versions for each versioned filter chain.
    pub Vec<&'a base64_set::Set>,
);

impl<'a> ValidateFilterChainVersions<'_> {
    pub fn validate(self) -> Result<(), ValidationError> {
        // Check for any version duplicates across all filter chains.
        let num_versions = self
            .0
            .iter()
            .map(|versions| versions.iter().collect::<Vec<_>>())
            .flatten()
            .count();
        let num_versions_without_duplicates = self
            .0
            .iter()
            .copied()
            .flatten()
            .collect::<HashSet<_>>()
            .len();

        if num_versions != num_versions_without_duplicates {
            return Err(ValidationError::NotUnique(
                "filter chain versions".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::Value;

    use super::*;

    use crate::endpoint::Metadata;
    use std::collections::BTreeSet;

    fn parse_config(yaml: &str) -> Config {
        Config::from_reader(yaml.as_bytes()).unwrap()
    }

    fn assert_static_endpoints(source: &Source, expected_endpoints: Vec<Endpoint>) {
        match source {
            Source::Static {
                filter_chain: _,
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
                filter_chain: _,
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
                vec![Endpoint::new("127.0.0.1:25999".parse().unwrap())],
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
                    Endpoint::new("127.0.0.1:26000".parse().unwrap()),
                    Endpoint::new("127.0.0.1:26001".parse().unwrap()),
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
        assert!(config.proxy.id.len() > 1);
    }

    #[test]
    fn parse_non_versioned_filter_chain() {
        let yaml = "
version: v1alpha1
proxy:
  id: client-proxy
  port: 7000 # the port to receive traffic to locally
static:
  filter_chain:
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

        let filter = config
            .source
            .get_static_non_versioned_filters()
            .unwrap()
            .get(0)
            .unwrap();
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
        assert!(could.get(3).unwrap().as_bool().unwrap());
    }

    #[test]
    fn parse_static_versioned_filter_chain() {
        let yaml = "
version: v1alpha1
proxy:
  port: 7000
static:
  filter_chain:
    versioned:
      capture_version:
        strategy: PREFIX
        size: 1
      filter_chains:
      - versions:
        - AA==
        - AQ==
        filters:
        - name: quilkin.core.v1.test1
          config:
            id: test1
        - name: quilkin.core.v1.test2
          config:
            id: test2
      - versions:
        - Ag==
        filters:
        - name: quilkin.core.v1.test3
          config:
            id: test3
  endpoints:
  - address: 127.0.0.1:7001
        ";
        let config = parse_config(yaml);

        let capture_version = config.source.get_capture_version().unwrap();
        assert_eq!(
            CaptureVersion {
                strategy: Strategy::Prefix,
                size: 1,
                remove: true
            },
            capture_version
        );

        let filter_chains = config.source.get_static_versioned_filters().unwrap();

        assert_eq!(2, filter_chains.len());

        let filter_chain_1 = filter_chains.get(0).unwrap();
        let filter_chain_2 = filter_chains.get(1).unwrap();

        let versions_1 = vec![vec![0], vec![1]].into_iter().collect::<BTreeSet<_>>();
        assert_eq!(versions_1, filter_chain_1.versions);
        assert_eq!(2, filter_chain_1.filters.len());
        let filter_1 = &filter_chain_1.filters[0];
        assert_eq!("quilkin.core.v1.test1", filter_1.name);
        let config_1 = filter_1.config.as_ref().unwrap();
        assert_eq!(
            serde_json::json!({
                "id": "test1"
            }),
            serde_json::to_value(config_1).unwrap()
        );

        let filter_2 = &filter_chain_1.filters[1];
        assert_eq!("quilkin.core.v1.test2", filter_2.name);
        let config_2 = filter_2.config.as_ref().unwrap();
        assert_eq!(
            serde_json::json!({
                "id": "test2"
            }),
            serde_json::to_value(config_2).unwrap()
        );

        let versions_2 = vec![vec![2]].into_iter().collect::<BTreeSet<_>>();
        assert_eq!(versions_2, filter_chain_2.versions);
        assert_eq!(1, filter_chain_2.filters.len());
        let filter_3 = &filter_chain_2.filters[0];
        assert_eq!("quilkin.core.v1.test3", filter_3.name);
        let config_3 = filter_3.config.as_ref().unwrap();
        assert_eq!(
            serde_json::json!({
                "id": "test3"
            }),
            serde_json::to_value(config_3).unwrap()
        );
    }

    #[test]
    fn parse_static_filter_chain_default() {
        let yaml = "
version: v1alpha1
proxy:
  port: 7000
static:
  endpoints:
  - address: 127.0.0.1:7001
        ";
        let config = parse_config(yaml);

        let filter_chains = config.source.get_static_non_versioned_filters().unwrap();

        assert_eq!(0, filter_chains.len());
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
    - address: 127.0.0.1:25999
  ";
        let config = parse_config(yaml);

        assert_static_endpoints(
            &config.source,
            vec![Endpoint::new("127.0.0.1:25999".parse().unwrap())],
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
    fn parse_dynamic_management_servers() {
        let yaml = "
version: v1alpha1
dynamic:
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

    #[test]
    fn parse_dynamic_filter_chain() {
        let yaml = "
version: v1alpha1
dynamic:
  filter_chain:
    versioned:
      capture_version:
        strategy: SUFFIX
        size: 1
  management_servers:
    - address: 127.0.0.1:25999
";
        let config = parse_config(yaml);

        let capture_version = config.source.get_capture_version().unwrap();
        assert_eq!(
            CaptureVersion {
                strategy: Strategy::Suffix,
                size: 1,
                remove: true
            },
            capture_version
        );

        assert_management_servers(
            &config.source,
            vec![ManagementServer {
                address: "127.0.0.1:25999".into(),
            }],
        );
    }

    #[test]
    fn deny_unused_fields() {
        let configs = vec![
            "
version: v1alpha1
foo: bar
static:
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
static:
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
static:
  endpoints:
    - address: 127.0.0.1:7001
      connection_ids:
      - Mxg3aWp5Ng==
",
            "
# static.filters
version: v1alpha1
static:
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
            assert!(format!("{:?}", error).contains("unknown field"));
        }
    }
}
