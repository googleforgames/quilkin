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

use std::{net::IpAddr, sync::Arc};

use base64_serde::base64_serde_type;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    filters::prelude::*,
    net::cluster::ClusterMap,
    net::xds::{
        config::listener::v3::Listener, service::discovery::v3::DiscoveryResponse, Resource,
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

base64_serde_type!(pub Base64Standard, base64::engine::general_purpose::STANDARD);

pub(crate) const BACKOFF_INITIAL_DELAY_MILLISECONDS: u64 = 500;
pub(crate) const BACKOFF_MAX_DELAY_SECONDS: u64 = 30;
pub(crate) const BACKOFF_MAX_JITTER_MILLISECONDS: u64 = 2000;
pub(crate) const CONNECTION_TIMEOUT: u64 = 5;

/// Config is the configuration of a proxy
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    #[serde(default)]
    pub clusters: Watch<ClusterMap>,
    #[serde(default, skip)]
    pub num_of_available_endpoints: Slot<usize>,
    #[serde(default)]
    pub filters: Slot<crate::filters::FilterChain>,
    #[serde(default = "default_proxy_id")]
    pub id: Slot<String>,
    #[serde(default)]
    pub version: Slot<Version>,
    #[serde(default)]
    pub datacenters: Watch<DatacenterMap>,
    #[serde(default)]
    pub icao_code: Slot<IcaoCode>,
    #[serde(default)]
    pub qcmp_port: Slot<u16>,
}

impl Config {
    /// Attempts to deserialize `input` as a YAML object representing `Self`.
    pub fn from_reader<R: std::io::Read>(input: R) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_reader(input)
    }

    fn update_from_json(
        &self,
        map: serde_json::Map<String, serde_json::Value>,
        locality: Option<crate::net::endpoint::Locality>,
    ) -> Result<(), eyre::Error> {
        macro_rules! replace_if_present {
            ($($field:ident),+) => {
                $(
                    if let Some(value) = map.get(stringify!($field)) {
                        tracing::debug!(%value, "replacing {}", stringify!($field));
                        self.$field.try_replace(serde_json::from_value(value.clone())?);
                    }
                )+
            }
        }

        replace_if_present!(filters, id);

        if let Some(value) = map.get("clusters").cloned() {
            tracing::debug!(%value, "replacing clusters");
            let value: ClusterMap = serde_json::from_value(value)?;
            self.clusters.modify(|clusters| {
                for cluster in value.iter() {
                    clusters.merge(cluster.key().clone(), cluster.value().clone());
                }

                if let Some(locality) = locality {
                    clusters.update_unlocated_endpoints(locality);
                }
            });
            self.num_of_available_endpoints
                .store((*self.clusters.read()).num_of_endpoints().into());
        }

        self.apply_metrics();

        Ok(())
    }

    pub fn discovery_request(
        &self,
        mode: &crate::cli::Admin,
        _node_id: &str,
        resource_type: ResourceType,
        names: &[String],
    ) -> Result<DiscoveryResponse, eyre::Error> {
        let mut resources = Vec::new();
        match resource_type {
            ResourceType::Datacenter => {
                if mode.is_agent() {
                    resources.push(resource_type.encode_to_any(
                        &crate::net::cluster::proto::Datacenter {
                            qcmp_port: u16::clone(&self.qcmp_port.load()).into(),
                            icao_code: self.icao_code.load().to_string(),
                            ..<_>::default()
                        },
                    )?);
                } else {
                    for entry in self.datacenters.read().iter() {
                        resources.push(resource_type.encode_to_any(
                            &crate::net::cluster::proto::Datacenter {
                                host: entry.key().to_string(),
                                qcmp_port: entry.qcmp_port.into(),
                                icao_code: entry.icao_code.to_string(),
                            },
                        )?);
                    }
                }
            }
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
                                cluster.value(),
                            ))?,
                        )?);
                    }
                } else {
                    for locality in names.iter().filter_map(|name| name.parse().ok()) {
                        if let Some(cluster) = self.clusters.read().get(&Some(locality)) {
                            resources.push(resource_type.encode_to_any(
                                &crate::net::cluster::proto::Cluster::try_from((
                                    cluster.key(),
                                    cluster.value(),
                                ))?,
                            )?);
                        }
                    }
                };
            }
        };

        Ok(DiscoveryResponse {
            resources,
            type_url: resource_type.type_url().into(),
            ..<_>::default()
        })
    }

    pub fn apply(&self, response: &Resource) -> crate::Result<()> {
        tracing::trace!(resource=?response, "applying resource");

        match response {
            Resource::Listener(listener) => {
                let chain = listener
                    .filter_chains
                    .get(0)
                    .map(|chain| chain.filters.clone())
                    .unwrap_or_default()
                    .into_iter()
                    .map(Filter::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                self.filters.store(Arc::new(chain.try_into()?));
            }
            Resource::Datacenter(dc) => {
                let host = dc.host.parse()?;
                self.datacenters.write().insert(
                    host,
                    Datacenter {
                        qcmp_port: dc.qcmp_port.try_into()?,
                        icao_code: dc.icao_code.parse()?,
                    },
                );
            }
            Resource::Cluster(cluster) => {
                self.clusters.write().merge(
                    cluster.locality.clone().map(From::from),
                    cluster
                        .endpoints
                        .iter()
                        .cloned()
                        .map(crate::net::endpoint::Endpoint::try_from)
                        .collect::<Result<_, _>>()?,
                );
                self.num_of_available_endpoints
                    .store((*self.clusters.read()).num_of_endpoints().into());
            }
        }

        self.apply_metrics();

        Ok(())
    }

    fn watch_clusters(&self) {
        let mut watcher = self.clusters.watch();
        let clusters = self.clusters.clone();
        let count = self.num_of_available_endpoints.clone();
        tokio::spawn(async move {
            loop {
                if let Err(error) = watcher.changed().await {
                    tracing::error!(%error, "error watching changes");
                }
                count.store(clusters.read().num_of_endpoints().into());
            }
        });
    }

    pub fn apply_metrics(&self) {
        let clusters = self.clusters.read();
        crate::net::cluster::active_clusters().set(clusters.len() as i64);
        crate::net::cluster::active_endpoints().set(clusters.endpoints().count() as i64);
    }
}

impl Default for Config {
    fn default() -> Self {
        let this = Self {
            clusters: <_>::default(),
            filters: <_>::default(),
            num_of_available_endpoints: <_>::default(),
            id: default_proxy_id(),
            version: Slot::with_default(),
            datacenters: <_>::default(),
            qcmp_port: <_>::default(),
            icao_code: <_>::default(),
        };

        this.watch_clusters();

        this
    }
}

#[derive(Clone, Default, Debug, Deserialize, Serialize)]
pub struct DatacenterMap(dashmap::DashMap<IpAddr, Datacenter>);

impl std::ops::Deref for DatacenterMap {
    type Target = dashmap::DashMap<IpAddr, Datacenter>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl schemars::JsonSchema for DatacenterMap {
    fn schema_name() -> String {
        <std::collections::HashMap<IpAddr, Datacenter>>::schema_name()
    }
    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <std::collections::HashMap<IpAddr, Datacenter>>::json_schema(gen)
    }

    fn is_referenceable() -> bool {
        <std::collections::HashMap<IpAddr, Datacenter>>::is_referenceable()
    }
}

impl PartialEq for DatacenterMap {
    fn eq(&self, rhs: &Self) -> bool {
        if self.0.len() != rhs.0.len() {
            return false;
        }

        for a in self.iter() {
            match rhs.get(a.key()).filter(|b| *a.value() == **b) {
                Some(_) => {}
                None => return false,
            }
        }

        true
    }
}

#[derive(Clone, Debug, PartialEq, JsonSchema, Serialize, Deserialize)]
pub struct Datacenter {
    pub qcmp_port: u16,
    pub icao_code: IcaoCode,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
pub struct IcaoCode(String);

impl Default for IcaoCode {
    fn default() -> Self {
        Self("XXXX".to_owned())
    }
}

impl std::str::FromStr for IcaoCode {
    type Err = eyre::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() == 4 {
            Ok(Self(input.to_owned()))
        } else {
            Err(eyre::eyre!("invalid ICAO code"))
        }
    }
}

impl std::fmt::Display for IcaoCode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.fmt(f)
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

    #[tokio::test]
    async fn deserialise_client() {
        let config = Config::default();
        config.clusters.modify(|clusters| {
            clusters.insert_default([Endpoint::new("127.0.0.1:25999".parse().unwrap())].into())
        });

        let _ = serde_yaml::to_string(&config).unwrap();
    }

    #[tokio::test]
    async fn deserialise_server() {
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
