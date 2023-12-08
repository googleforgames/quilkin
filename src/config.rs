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

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

use base64_serde::base64_serde_type;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    filters::prelude::*,
    net::cluster::{self, ClusterMap},
    net::xds::{
        config::listener::v3::Listener, service::discovery::v3::Resource as XdsResource, Resource,
        ResourceType,
    },
};

pub use self::{
    config_type::ConfigType, error::ValidationError, providers::Providers, slot::Slot, watch::Watch,
};

mod config_type;
mod error;
pub mod providers;
mod slot;
pub mod watch;
pub(crate) mod xds;

base64_serde_type!(pub Base64Standard, base64::engine::general_purpose::STANDARD);

pub(crate) const BACKOFF_INITIAL_DELAY_MILLISECONDS: u64 = 500;
pub(crate) const BACKOFF_MAX_DELAY_SECONDS: u64 = 30;
pub(crate) const BACKOFF_MAX_JITTER_MILLISECONDS: u64 = 2000;
pub(crate) const CONNECTION_TIMEOUT: u64 = 5;

/// Returns the configured maximum allowed message size for gRPC messages.
/// When using State Of The World xDS, the message size can get large enough
/// that it can exceed the default limits.
pub fn max_grpc_message_size() -> usize {
    std::env::var("QUILKIN_MAX_GRPC_MESSAGE_SIZE")
        .as_deref()
        .ok()
        .and_then(|var| var.parse().ok())
        .unwrap_or(256 * 1024 * 1024)
}

/// Config is the configuration of a proxy
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    #[serde(default)]
    pub clusters: Watch<ClusterMap>,
    #[serde(default)]
    pub filters: Slot<crate::filters::FilterChain>,
    #[serde(default = "default_proxy_id")]
    pub id: Slot<String>,
    #[serde(default)]
    pub version: Slot<Version>,
}

pub struct DeltaDiscoveryRes {
    pub resources: Vec<XdsResource>,
    pub awaiting_ack: crate::net::xds::AwaitingAck,
    pub removed: Vec<String>,
}

impl Config {
    /// Attempts to deserialize `input` as a YAML object representing `Self`.
    pub fn from_reader<R: std::io::Read>(input: R) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_reader(input)
    }

    fn update_from_json(
        &self,
        mut map: serde_json::Map<String, serde_json::Value>,
        locality: Option<crate::net::endpoint::Locality>,
    ) -> Result<(), eyre::Error> {
        macro_rules! replace_if_present {
            ($($field:ident),+) => {
                $(
                    if let Some(value) = map.remove(stringify!($field)) {
                        tracing::debug!(%value, "replacing {}", stringify!($field));
                        self.$field.try_replace(serde_json::from_value(value)?);
                    }
                )+
            }
        }

        replace_if_present!(filters, id);

        if let Some(value) = map.remove("clusters") {
            tracing::debug!(%value, "replacing clusters");
            let cmd: cluster::ClusterMapDeser = serde_json::from_value(value)?;
            self.clusters.modify(|clusters| {
                for cluster in cmd.endpoints {
                    clusters.insert(cluster.locality, cluster.endpoints);
                }

                if let Some(locality) = locality {
                    clusters.update_unlocated_endpoints(locality);
                }
            });
        }

        self.apply_metrics();

        Ok(())
    }

    pub fn discovery_request(
        &self,
        _id: &str,
        resource_type: ResourceType,
        names: &[String],
    ) -> Result<Vec<prost_types::Any>, eyre::Error> {
        let mut resources = Vec::new();

        match resource_type {
            ResourceType::Listener => {
                resources.push(resource_type.encode_to_any(&Listener {
                    filter_chains: vec![(&*self.filters.load()).try_into()?],
                    ..<_>::default()
                })?);
            }
            ResourceType::Cluster => {
                if names.is_empty() {
                    for cluster in self.clusters.read().iter() {
                        resources.push(resource_type.encode_to_any(
                            &crate::net::cluster::proto::Cluster::try_from((
                                cluster.key(),
                                &cluster.value().endpoints,
                            ))?,
                        )?);
                    }
                } else {
                    for locality in names.iter().filter_map(|name| name.parse().ok()) {
                        if let Some(cluster) = self.clusters.read().get(&Some(locality)) {
                            resources.push(resource_type.encode_to_any(
                                &crate::net::cluster::proto::Cluster::try_from((
                                    cluster.key(),
                                    &cluster.value().endpoints,
                                ))?,
                            )?);
                        }
                    }
                };
            }
        }

        Ok(resources)
    }

    /// Given a list of subscriptions and the current state of the calling client,
    /// construct a response with the current state of our resources that differ
    /// from those of the client
    pub fn delta_discovery_request(
        &self,
        subscribed: &BTreeSet<String>,
        client_versions: &crate::net::xds::ClientVersions,
    ) -> crate::Result<DeltaDiscoveryRes> {
        let mut resources = Vec::new();

        let (awaiting_ack, removed) = match client_versions {
            crate::net::xds::ClientVersions::Listener => {
                resources.push(XdsResource {
                    name: "listener".into(),
                    version: "0".into(),
                    resource: Some(ResourceType::Listener.encode_to_any(&Listener {
                        filter_chains: vec![(&*self.filters.load()).try_into()?],
                        ..<_>::default()
                    })?),
                    aliases: Vec::new(),
                    ttl: None,
                    cache_control: None,
                });
                (crate::net::xds::AwaitingAck::Listener, Vec::new())
            }
            crate::net::xds::ClientVersions::Cluster(map) => {
                let resource_type = ResourceType::Cluster;
                let mut to_ack = Vec::new();

                let mut push = |key: &Option<crate::net::endpoint::Locality>,
                                value: &crate::net::cluster::EndpointSet|
                 -> crate::Result<()> {
                    let current_version = value.version();
                    if let Some(client_version) = map.get(key) {
                        if current_version == *client_version {
                            return Ok(());
                        }
                    }

                    resources.push(XdsResource {
                        name: key.as_ref().map(|k| k.to_string()).unwrap_or_default(),
                        version: current_version.to_string(),
                        resource: Some(resource_type.encode_to_any(
                            &crate::net::cluster::proto::Cluster::try_from((
                                key,
                                &value.endpoints,
                            ))?,
                        )?),
                        ..Default::default()
                    });
                    to_ack.push((key.clone(), current_version));

                    Ok(())
                };

                if subscribed.is_empty() {
                    for cluster in self.clusters.read().iter() {
                        push(cluster.key(), cluster.value())?;
                    }
                } else {
                    for locality in subscribed.iter().filter_map(|name| name.parse().ok()) {
                        if let Some(cluster) = self.clusters.read().get(&Some(locality)) {
                            push(cluster.key(), cluster.value())?;
                        }
                    }
                };

                // Currently, we have exactly _one_ special case for removed resources, which
                // is when ClusterMap::update_unlocated_endpoints is called to move the None
                // locality endpoints to another one, so we just detect that case manually
                let removed: Vec<_> = (map.contains_key(&None)
                    && self.clusters.read().get(&None).is_none())
                .then_some(String::new())
                .into_iter()
                .collect();

                (
                    crate::net::xds::AwaitingAck::Cluster {
                        updated: to_ack,
                        remove_none: !removed.is_empty(),
                    },
                    removed,
                )
            }
        };

        Ok(DeltaDiscoveryRes {
            resources,
            awaiting_ack,
            removed,
        })
    }

    #[tracing::instrument(skip_all, fields(response = response.type_url()))]
    pub fn apply(&self, response: Resource) -> crate::Result<()> {
        tracing::trace!(resource=?response, "applying resource");

        match response {
            Resource::Listener(mut listener) => {
                let chain: crate::filters::FilterChain = if listener.filter_chains.is_empty() {
                    Default::default()
                } else {
                    crate::filters::FilterChain::try_create_fallible(
                        listener.filter_chains.swap_remove(0).filters.into_iter(),
                    )?
                };

                self.filters.store(Arc::new(chain));
            }
            Resource::Cluster(cluster) => {
                self.clusters.write().insert(
                    cluster.locality.map(From::from),
                    cluster
                        .endpoints
                        .into_iter()
                        .map(crate::net::endpoint::Endpoint::try_from)
                        .collect::<Result<_, _>>()?,
                );
            }
        }

        self.apply_metrics();

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(response = resource_type.type_url()))]
    pub fn apply_delta(
        &self,
        resource_type: ResourceType,
        resources: impl Iterator<Item = crate::Result<(Resource, String)>>,
        removed_resources: Vec<String>,
        local_versions: &mut HashMap<String, String>,
    ) -> crate::Result<()> {
        // Remove any resources the upstream server has removed/doesn't have,
        // we do this before applying any new/updated resources in case a
        // resource is in both lists, though really that would be a bug in
        // the upstream server
        for removed in &removed_resources {
            local_versions.remove(removed);
        }

        match resource_type {
            ResourceType::Listener => {
                for res in resources {
                    let (resource, _) = res?;
                    let Resource::Listener(mut listener) = resource else {
                        return Err(eyre::eyre!("a non-listener resource was present"));
                    };

                    let chain: crate::filters::FilterChain = if listener.filter_chains.is_empty() {
                        Default::default()
                    } else {
                        crate::filters::FilterChain::try_create_fallible(
                            listener.filter_chains.swap_remove(0).filters.into_iter(),
                        )?
                    };

                    self.filters.store(Arc::new(chain));
                    local_versions.insert(listener.name, "".into());
                }
            }
            ResourceType::Cluster => self.clusters.modify(|guard| {
                for removed in removed_resources {
                    let locality = if removed.is_empty() {
                        None
                    } else {
                        Some(removed.parse()?)
                    };
                    guard.remove_locality(&locality);
                }

                for res in resources {
                    let (resource, version) = res?;

                    let Resource::Cluster(cluster) = resource else {
                        return Err(eyre::eyre!("a non-cluster resource was present"));
                    };

                    let parsed_version = version.parse()?;

                    let endpoints = crate::config::cluster::EndpointSet::with_version(
                        cluster
                            .endpoints
                            .into_iter()
                            .map(crate::net::endpoint::Endpoint::try_from)
                            .collect::<Result<_, _>>()?,
                        parsed_version,
                    );

                    let locality = cluster.locality.map(crate::net::endpoint::Locality::from);
                    let name = locality.as_ref().map(|l| l.to_string()).unwrap_or_default();

                    guard.apply(locality, endpoints);
                    local_versions.insert(name, version);
                }

                Ok(())
            })?,
        }

        self.apply_metrics();
        Ok(())
    }

    #[inline]
    pub fn apply_metrics(&self) {
        let clusters = self.clusters.read();
        crate::net::cluster::active_clusters().set(clusters.len() as i64);
        crate::net::cluster::active_endpoints().set(clusters.num_of_endpoints() as i64);
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            clusters: <_>::default(),
            filters: <_>::default(),
            id: default_proxy_id(),
            version: Slot::with_default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Serialize, JsonSchema, PartialEq)]
pub enum Version {
    #[serde(rename = "v1alpha1")]
    V1Alpha1,
}

impl Default for Version {
    fn default() -> Self {
        Self::V1Alpha1
    }
}

#[cfg(not(target_os = "linux"))]
fn default_proxy_id() -> Slot<String> {
    Slot::from(Uuid::new_v4().as_hyphenated().to_string())
}

#[cfg(target_os = "linux")]
fn default_proxy_id() -> Slot<String> {
    Slot::from(sys_info::hostname().unwrap_or_else(|_| Uuid::new_v4().as_hyphenated().to_string()))
}

/// Filter is the configuration for a single filter
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub name: String,
    pub label: Option<String>,
    pub config: Option<serde_json::Value>,
}

impl TryFrom<crate::net::xds::config::listener::v3::Filter> for Filter {
    type Error = CreationError;

    fn try_from(
        filter: crate::net::xds::config::listener::v3::Filter,
    ) -> Result<Self, Self::Error> {
        use crate::net::xds::config::listener::v3::filter::ConfigType;

        let config = if let Some(config_type) = filter.config_type {
            let config = match config_type {
                ConfigType::TypedConfig(any) => any,
                ConfigType::ConfigDiscovery(_) => {
                    return Err(CreationError::FieldInvalid {
                        field: "config_type".into(),
                        reason: "ConfigDiscovery is currently unsupported".into(),
                    })
                }
            };
            Some(
                crate::filters::FilterRegistry::get_factory(&filter.name)
                    .ok_or_else(|| CreationError::NotFound(filter.name.clone()))?
                    .encode_config_to_json(config)?,
            )
        } else {
            None
        };

        Ok(Self {
            name: filter.name,
            // TODO: keep the label across xDS
            label: None,
            config,
        })
    }
}

impl TryFrom<Filter> for crate::net::xds::config::listener::v3::Filter {
    type Error = CreationError;

    fn try_from(filter: Filter) -> Result<Self, Self::Error> {
        use crate::net::xds::config::listener::v3::filter::ConfigType;

        let config = if let Some(config) = filter.config {
            Some(
                crate::filters::FilterRegistry::get_factory(&filter.name)
                    .ok_or_else(|| CreationError::NotFound(filter.name.clone()))?
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

impl From<(String, FilterInstance)> for Filter {
    fn from((name, instance): (String, FilterInstance)) -> Self {
        Self {
            name,
            label: instance.label().map(String::from),
            config: Some(serde_json::Value::clone(instance.config())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use serde_json::json;

    use crate::net::endpoint::{Endpoint, Metadata};

    use super::*;

    fn parse_config(yaml: &str) -> Config {
        Config::from_reader(yaml.as_bytes()).unwrap()
    }

    #[test]
    fn deserialise_client() {
        let config = Config::default();
        config.clusters.modify(|clusters| {
            clusters.insert_default([Endpoint::new("127.0.0.1:25999".parse().unwrap())].into())
        });

        let _ = serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn deserialise_server() {
        let config = Config::default();
        config.clusters.modify(|clusters| {
            clusters.insert_default(
                [
                    Endpoint::new("127.0.0.1:26000".parse().unwrap()),
                    Endpoint::new("127.0.0.1:26001".parse().unwrap()),
                ]
                .into(),
            )
        });

        let _ = serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn parse_default_values() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
             "clusters":[]
        }))
        .unwrap();

        assert!(config.id.load().len() > 1);
    }

    #[test]
    fn parse_proxy() {
        let yaml = "
version: v1alpha1
id: server-proxy
  ";
        let config = parse_config(yaml);

        assert_eq!(config.id.load().as_str(), "server-proxy");
        assert_eq!(*config.version.load(), Version::V1Alpha1);
    }

    #[test]
    fn parse_client() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "clusters": [{
                "endpoints": [{
                    "address": "127.0.0.1:25999"
                }],
            }]
        }))
        .unwrap();

        let value = config.clusters.read();
        assert_eq!(
            &*value,
            &ClusterMap::new_default(
                [Endpoint::new((std::net::Ipv4Addr::LOCALHOST, 25999).into(),)].into()
            )
        )
    }

    #[test]
    fn parse_ipv6_endpoint() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "clusters":[{
                "endpoints": [{
                    "address": "[2345:0425:2CA1:0000:0000:0567:5673:24b5]:25999"
                }],
            }]
        }))
        .unwrap();

        let value = config.clusters.read();
        assert_eq!(
            &*value,
            &ClusterMap::new_default(
                [Endpoint::new(
                    (
                        "2345:0425:2CA1:0000:0000:0567:5673:24b5"
                            .parse::<Ipv6Addr>()
                            .unwrap(),
                        25999
                    )
                        .into()
                )]
                .into()
            )
        )
    }

    #[test]
    fn parse_server() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "clusters": [{
                "endpoints": [
                    {
                        "address" : "127.0.0.1:26000",
                        "metadata": {
                            "quilkin.dev": {
                                "tokens": ["MXg3aWp5Ng==", "OGdqM3YyaQ=="],
                            }
                        }
                    },
                    {
                        "address" : "[2345:0425:2CA1:0000:0000:0567:5673:24b5]:25999",
                        "metadata": {
                            "quilkin.dev": {
                                "tokens": ["bmt1eTcweA=="],
                            }
                        }
                    }
                ],
            }]
        }))
        .unwrap_or_default();

        let value = config.clusters.read();
        assert_eq!(
            &*value,
            &ClusterMap::new_default(
                [
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
                        "[2345:0425:2CA1:0000:0000:0567:5673:24b5]:25999"
                            .parse()
                            .unwrap(),
                        Metadata {
                            tokens: vec!["nkuy70x"].into_iter().map(From::from).collect(),
                        },
                    ),
                ]
                .into()
            )
        );
    }

    #[test]
    fn deny_unused_fields() {
        let configs = vec![
            "
version: v1alpha1
foo: bar
clusters:
    - endpoints:
        - address: 127.0.0.1:7001
",
            "
# proxy
version: v1alpha1
foo: bar
id: client-proxy
port: 7000
clusters:
    - endpoints:
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
clusters:
    - endpoints:
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
            println!("here: {}", error);
            assert!(format!("{error:?}").contains("unknown field"));
        }
    }
}
