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
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};

use base64_serde::base64_serde_type;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    filters::prelude::*,
    generated::envoy::service::discovery::v3::Resource as XdsResource,
    net::cluster::{self, ClusterMap},
};

pub use self::{
    config_type::ConfigType, error::ValidationError, providers::Providers, slot::Slot, watch::Watch,
};

mod config_type;
mod error;
pub mod providers;
mod slot;
pub mod watch;

pub(crate) const BACKOFF_INITIAL_DELAY: Duration = Duration::from_millis(500);

base64_serde_type!(pub Base64Standard, base64::engine::general_purpose::STANDARD);

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
#[cfg_attr(test, derive(PartialEq))]
pub enum DatacenterConfig {
    NonAgent {
        #[serde(default)]
        datacenters: Watch<DatacenterMap>,
    },
    Agent {
        #[serde(default)]
        icao_code: Slot<IcaoCode>,
        #[serde(default)]
        qcmp_port: Slot<u16>,
    },
}

/// Configuration for a component
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
    #[serde(flatten)]
    pub datacenter: DatacenterConfig,
}

impl xds::config::Configuration for Config {
    fn identifier(&self) -> String {
        (*self.id.load()).clone()
    }

    fn allow_request_processing(&self, resource_type: &str) -> bool {
        resource_type
            .parse::<crate::xds::ResourceType>()
            .is_ok()
    }

    fn apply_delta(
        &self,
        type_url: &str,
        resources: Vec<XdsResource>,
        removed_resources: Vec<String>,
        local_versions: &mut HashMap<String, String>,
        remote_addr: Option<std::net::SocketAddr>,
    ) -> xds::Result<()> {
        self.apply_delta(
            type_url,
            resources,
            removed_resources,
            local_versions,
            remote_addr,
        )
    }

    fn delta_discovery_request(
        &self,
        client_state: &xds::config::ClientState,
    ) -> xds::Result<DeltaDiscoveryRes> {
        self.delta_discovery_request(client_state)
    }

    fn interested_resources(&self) -> impl Iterator<Item = (&'static str, Vec<String>)> {
        [
            (crate::xds::CLUSTER_TYPE, Vec::new()),
            (crate::xds::DATACENTER_TYPE, Vec::new()),
        ].into_iter()
    }

    fn on_changed(
        &self,
        control_plane: xds::server::ControlPlane<Self>,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut cluster_watcher = self.clusters.watch();

        if !control_plane.is_relay {
            self.filters.watch({
                let this = control_plane.clone();
                move |_| {
                    this.push_update(crate::xds::FILTER_CHAIN_TYPE);
                }
            });
        }

        tracing::trace!("waiting for changes");

        async move {
            match &control_plane.config.datacenter {
                crate::config::DatacenterConfig::Agent { .. } => loop {
                    match cluster_watcher.changed().await {
                        Ok(()) => control_plane.push_update(crate::xds::CLUSTER_TYPE),
                        Err(error) => tracing::error!(%error, "error watching changes"),
                    }
                },
                crate::config::DatacenterConfig::NonAgent { datacenters } => {
                    let mut dc_watcher = datacenters.watch();
                    loop {
                        tokio::select! {
                            result = cluster_watcher.changed() => {
                                match result {
                                    Ok(()) => control_plane.push_update(crate::xds::CLUSTER_TYPE),
                                    Err(error) => tracing::error!(%error, "error watching changes"),
                                }
                            }
                            result = dc_watcher.changed() => {
                                match result {
                                    Ok(()) => control_plane.push_update(crate::xds::DATACENTER_TYPE),
                                    Err(error) => tracing::error!(%error, "error watching changes"),
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

use crate::net::xds::config::DeltaDiscoveryRes;

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
                        tracing::trace!(%value, "replacing {}", stringify!($field));
                        self.$field.try_replace(serde_json::from_value(value)?);
                    }
                )+
            }
        }

        replace_if_present!(filters, id);

        if let Some(value) = map.remove("clusters") {
            let cmd: cluster::ClusterMapDeser = serde_json::from_value(value)?;
            tracing::trace!(len = cmd.endpoints.len(), "replacing clusters");
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

    /// Given a list of subscriptions and the current state of the calling client,
    /// construct a response with the current state of our resources that differ
    /// from those of the client
    pub fn delta_discovery_request(
        &self,
        client_state: &xds::config::ClientState,
    ) -> crate::Result<DeltaDiscoveryRes> {
        let mut resources = Vec::new();
        let mut removed = std::collections::HashSet::new();

        let resource_type: crate::xds::ResourceType =
            client_state.resource_type.parse()?;

        'append: {
            match resource_type {
                crate::xds::ResourceType::FilterChain => {
                    let resource = crate::xds::Resource::FilterChain(
                        crate::net::cluster::proto::FilterChain::try_from(&*self.filters.load())?,
                    );
                    let any = resource.try_encode()?;
                    let version = seahash::hash(&any.value);

                    let vstr = version.to_string();

                    if client_state.version_matches("filter_chain", &vstr) {
                        break 'append;
                    }

                    resources.push(XdsResource {
                        name: "filter_chain".into(),
                        version: vstr,
                        resource: Some(any),
                        aliases: Vec::new(),
                        ttl: None,
                        cache_control: None,
                    });
                }
                crate::xds::ResourceType::Datacenter => match &self.datacenter {
                    DatacenterConfig::Agent {
                        qcmp_port,
                        icao_code,
                    } => {
                        let name = icao_code.load().to_string();
                        let qcmp_port = *qcmp_port.load();
                        let port_s = qcmp_port.to_string();

                        if client_state.version_matches(&name, &port_s) {
                            break 'append;
                        }

                        let resource = crate::xds::Resource::Datacenter(
                            crate::net::cluster::proto::Datacenter {
                                qcmp_port: qcmp_port as _,
                                icao_code: name.clone(),
                                ..Default::default()
                            },
                        );

                        resources.push(XdsResource {
                            name,
                            version: port_s,
                            resource: Some(resource.try_encode()?),
                            aliases: Vec::new(),
                            ttl: None,
                            cache_control: None,
                        });
                    }
                    DatacenterConfig::NonAgent { datacenters } => {
                        for entry in datacenters.read().iter() {
                            let host = entry.key().to_string();
                            let qcmp_port = entry.qcmp_port;
                            let version = format!("{}-{qcmp_port}", entry.icao_code);

                            if client_state.version_matches(&host, &version) {
                                continue;
                            }

                            let resource = crate::xds::Resource::Datacenter(
                                crate::net::cluster::proto::Datacenter {
                                    qcmp_port: qcmp_port as _,
                                    icao_code: entry.icao_code.to_string(),
                                    host: host.clone(),
                                },
                            );

                            resources.push(XdsResource {
                                name: host,
                                version,
                                resource: Some(resource.try_encode()?),
                                aliases: Vec::new(),
                                ttl: None,
                                cache_control: None,
                            });
                        }

                        {
                            let dc = datacenters.read();
                            for key in client_state.versions.keys() {
                                let Ok(addr) = key.parse() else {
                                    continue;
                                };
                                if dc.get(&addr).is_none() {
                                    removed.insert(key.clone());
                                }
                            }
                        }
                    }
                },
                crate::xds::ResourceType::Cluster => {
                    let mut push = |key: &Option<crate::net::endpoint::Locality>,
                                    value: &crate::net::cluster::EndpointSet|
                     -> crate::Result<()> {
                        let version = value.version().to_string();
                        let key_s = key.as_ref().map(|k| k.to_string()).unwrap_or_default();

                        if client_state.version_matches(&key_s, &version) {
                            return Ok(());
                        }

                        let resource = crate::xds::Resource::Cluster(
                            xds::generated::quilkin::config::v1alpha1::Cluster {
                                locality: key.clone().map(|l| l.into()),
                                endpoints: value.endpoints.iter().map(|ep| ep.into()).collect(),
                            },
                        );

                        resources.push(XdsResource {
                            name: key_s,
                            version,
                            resource: Some(resource.try_encode()?),
                            ..Default::default()
                        });

                        Ok(())
                    };

                    if client_state.subscribed.is_empty() {
                        for cluster in self.clusters.read().iter() {
                            push(cluster.key(), cluster.value())?;
                        }
                    } else {
                        for locality in client_state.subscribed.iter().filter_map(|name| {
                            if name.is_empty() {
                                Some(None)
                            } else {
                                name.parse().ok().map(Some)
                            }
                        }) {
                            if let Some(cluster) = self.clusters.read().get(&locality) {
                                push(cluster.key(), cluster.value())?;
                            }
                        }
                    };

                    // Currently, we have exactly _one_ special case for removed resources, which
                    // is when ClusterMap::update_unlocated_endpoints is called to move the None
                    // locality endpoints to another one, so we just detect that case manually
                    if client_state.versions.contains_key("")
                        && self.clusters.read().get(&None).is_none()
                    {
                        removed.insert("".into());
                    }
                }
            }
        }

        Ok(DeltaDiscoveryRes { resources, removed })
    }

    #[tracing::instrument(skip_all, fields(response = type_url))]
    pub fn apply_delta(
        &self,
        type_url: &str,
        mut resources: Vec<XdsResource>,
        removed_resources: Vec<String>,
        local_versions: &mut HashMap<String, String>,
        remote_addr: Option<std::net::SocketAddr>,
    ) -> crate::Result<()> {
        let resource_type: crate::xds::ResourceType = type_url.parse()?;

        // Remove any resources the upstream server has removed/doesn't have,
        // we do this before applying any new/updated resources in case a
        // resource is in both lists, though really that would be a bug in
        // the upstream server
        for removed in &removed_resources {
            local_versions.remove(removed);
        }

        match resource_type {
            crate::xds::ResourceType::FilterChain => {
                // Server should only ever send exactly one filter chain, more or less indicates a bug
                let Some(res) = resources.pop() else {
                    eyre::bail!("no resources in delta response");
                };

                eyre::ensure!(
                    resources.is_empty(),
                    "additional filter chain resources were present in delta response"
                );

                let Some(resource) = res.resource else {
                    eyre::bail!("filter chain response did not contain a resource payload");
                };

                let crate::xds::Resource::FilterChain(resource) =
                    crate::xds::Resource::try_decode(resource)?
                else {
                    eyre::bail!(
                        "filter chain response contained a non-FilterChain resource payload"
                    );
                };

                let fc =
                    crate::filters::FilterChain::try_create_fallible(resource.filters.into_iter())?;

                self.filters.store(Arc::new(fc));
                local_versions.insert(res.name, res.version);
            }
            crate::xds::ResourceType::Datacenter => {
                let DatacenterConfig::NonAgent { datacenters } = &self.datacenter else {
                    eyre::bail!("cannot apply delta datacenters resource to agent");
                };

                datacenters.modify(|wg| {
                    let remote_addr = remote_addr.map(|ra| ra.ip().to_canonical());

                    for res in resources {
                        let Some(resource) = res.resource else {
                            tracing::error!("a datacenter resource could not be applied because it didn't contain an actual payload");
                            continue;
                        };

                        let dc = match crate::xds::Resource::try_decode(resource) {
                            Ok(crate::xds::Resource::Datacenter(dc)) => dc,
                            Ok(other) => {
                                tracing::error!(kind = other.type_url(), "a datacenter resource could not be applied because the resource payload was not a datacenter");
                                continue;
                            }
                            Err(error) => {
                                tracing::error!(%error, "a datacenter resource could not be applied because the resource payload could not be decoded");
                                continue;
                            }
                        };
                        
                        let parse_payload = || -> crate::Result<(std::net::IpAddr, Datacenter)> {
                            let host: std::net::IpAddr = if let Some(ra) = remote_addr {
                                ra
                            }else {
                                 dc.host.parse()?
                            };
                            let dc = Datacenter {
                                qcmp_port: dc.qcmp_port.try_into()?,
                                icao_code: dc.icao_code.parse()?,
                            };

                            Ok((host, dc))
                        };

                        match parse_payload() {
                            Ok((host, datacenter)) => {
                                wg.insert(
                                    host,
                                    datacenter,
                                );
        
                                local_versions.insert(res.name, res.version);
                            }
                            Err(error) => {
                                tracing::error!(%error, "a datacenter resource could not be applied because the resource payload could not be parsed");
                                continue;
                            }
                        }
                    }
                });
            }
            crate::xds::ResourceType::Cluster => self.clusters.modify(|guard| -> crate::Result<()> {
                for removed in removed_resources {
                    let locality = if removed.is_empty() {
                        None
                    } else {
                        Some(removed.parse()?)
                    };
                    guard.remove_locality(&locality);
                }

                for res in resources {
                    let Some(resource) = res.resource else {
                        tracing::error!("a cluster resource could not be applied because it didn't contain an actual payload");
                        continue;
                    };

                    let cluster = match crate::xds::Resource::try_decode(resource) {
                        Ok(crate::xds::Resource::Cluster(c)) => c,
                        Ok(other) => {
                            tracing::error!(kind = other.type_url(), "a cluster resource could not be applied because the resource payload was not a cluster");
                            continue;
                        }
                        Err(error) => {
                            tracing::error!(%error, "a cluster resource could not be applied because the resource payload could not be decoded");
                            continue;
                        }
                    };

                    let parsed_version = res.version.parse()?;

                    let endpoints = match cluster
                            .endpoints
                            .into_iter()
                            .map(crate::net::endpoint::Endpoint::try_from)
                            .collect::<Result<_, _>>() {
                        Ok(eps) => eps,
                        Err(error) => {
                            tracing::error!(%error, "a cluster resource could not be applied because one or more endpoints could not be parsed");
                            continue;
                        }
                    };

                    let endpoints = crate::config::cluster::EndpointSet::with_version(
                        endpoints,
                        parsed_version,
                    );

                    let locality = cluster.locality.map(crate::net::endpoint::Locality::from);

                    guard.apply(locality, endpoints);
                    local_versions.insert(res.name, res.version);
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

    pub fn default_agent() -> Self {
        Self {
            clusters: Default::default(),
            filters: Default::default(),
            id: default_proxy_id(),
            version: Slot::with_default(),
            datacenter: DatacenterConfig::Agent {
                icao_code: Default::default(),
                qcmp_port: Default::default(),
            },
        }
    }

    pub fn default_non_agent() -> Self {
        Self {
            clusters: Default::default(),
            filters: Default::default(),
            id: default_proxy_id(),
            version: Slot::with_default(),
            datacenter: DatacenterConfig::NonAgent {
                datacenters: Default::default(),
            },
        }
    }

    /// Gets the datacenters, panicking if this is an agent config
    #[inline]
    pub fn datacenters(&self) -> &Watch<DatacenterMap> {
        match &self.datacenter {
            DatacenterConfig::NonAgent { datacenters } => datacenters,
            DatacenterConfig::Agent { .. } => {
                unreachable!("this should not be called on an agent");
            }
        }
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct DatacenterMap {
    map: dashmap::DashMap<IpAddr, Datacenter>,
    version: AtomicU64,
}

impl DatacenterMap {
    #[inline]
    pub fn insert(&self, ip: IpAddr, datacenter: Datacenter) -> Option<Datacenter> {
        let old = self.map.insert(ip, datacenter);
        self.version.fetch_add(1, Relaxed);
        old
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[inline]
    pub fn version(&self) -> u64 {
        self.version.load(Relaxed)
    }

    #[inline]
    pub fn get(&self, key: &IpAddr) -> Option<dashmap::mapref::one::Ref<IpAddr, Datacenter>> {
        self.map.get(key)
    }

    #[inline]
    pub fn iter(&self) -> dashmap::iter::Iter<IpAddr, Datacenter> {
        self.map.iter()
    }
}

impl Clone for DatacenterMap {
    fn clone(&self) -> Self {
        let map = self.map.clone();
        Self {
            map,
            version: <_>::default(),
        }
    }
}

impl crate::config::watch::Watchable for DatacenterMap {
    #[inline]
    fn mark(&self) -> crate::config::watch::Marker {
        crate::config::watch::Marker::Version(self.version())
    }

    #[inline]
    #[allow(irrefutable_let_patterns)]
    fn has_changed(&self, marker: crate::config::watch::Marker) -> bool {
        let crate::config::watch::Marker::Version(marked) = marker else {
            return false;
        };
        self.version() != marked
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
        if self.map.len() != rhs.map.len() {
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

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct IcaoCode([u8; 4]);

impl AsRef<str> for IcaoCode {
    fn as_ref(&self) -> &str {
        // SAFETY: We don't allow this to be constructed with an invalid utf-8 string
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl Default for IcaoCode {
    fn default() -> Self {
        Self([b'X', b'X', b'X', b'X'])
    }
}

impl std::str::FromStr for IcaoCode {
    type Err = eyre::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        const VALID_RANGE: std::ops::RangeInclusive<char> = 'A'..='Z';
        let mut arr = [0; 4];
        let mut i = 0;

        for c in input.chars() {
            eyre::ensure!(i < 4, "ICAO code is too long");
            eyre::ensure!(
                VALID_RANGE.contains(&c),
                "ICAO code contained invalid character '{c}'"
            );
            arr[i] = c as u8;
            i += 1;
        }

        eyre::ensure!(i == 4, "ICAO code was not long enough");
        Ok(Self(arr))
    }
}

use std::fmt;

impl fmt::Display for IcaoCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl fmt::Debug for IcaoCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl Serialize for IcaoCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for IcaoCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct IcaoVisitor;

        impl<'de> serde::de::Visitor<'de> for IcaoVisitor {
            type Value = IcaoCode;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 4-character, uppercase, alphabetical ASCII ICAO code")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(IcaoVisitor)
    }
}

impl schemars::JsonSchema for IcaoCode {
    fn schema_name() -> String {
        "IcaoCode".into()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = gen.subschema_for::<String>();
        if let schemars::schema::Schema::Object(schema_object) = &mut schema {
            if schema_object.has_type(schemars::schema::InstanceType::String) {
                let validation = schema_object.string();
                validation.pattern = Some(r"^[A-Z]{4}$".to_string());
            }
        }
        schema
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

use crate::generated::envoy::config::listener::v3 as listener;

impl TryFrom<listener::Filter> for Filter {
    type Error = CreationError;

    fn try_from(filter: listener::Filter) -> Result<Self, Self::Error> {
        use listener::filter::ConfigType;

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

impl TryFrom<crate::net::cluster::proto::Filter> for Filter {
    type Error = CreationError;

    fn try_from(value: crate::net::cluster::proto::Filter) -> Result<Self, Self::Error> {
        let config = if let Some(cfg) = value.config {
            Some(
                serde_json::from_str(&cfg)
                    .map_err(|err| CreationError::DeserializeFailed(err.to_string()))?,
            )
        } else {
            None
        };

        Ok(Self {
            name: value.name,
            label: value.label,
            config,
        })
    }
}

impl TryFrom<Filter> for listener::Filter {
    type Error = CreationError;

    fn try_from(filter: Filter) -> Result<Self, Self::Error> {
        use listener::filter::ConfigType;

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

#[derive(Clone, Debug)]
pub struct AddressSelector {
    pub name: String,
    pub kind: AddrKind,
}

#[derive(Copy, Clone, Debug)]
pub enum AddrKind {
    Ipv4,
    Ipv6,
    Any,
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
        let config = Config::default_non_agent();
        config.clusters.modify(|clusters| {
            clusters.insert_default([Endpoint::new("127.0.0.1:25999".parse().unwrap())].into())
        });

        let _ = serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn deserialise_server() {
        let config = Config::default_non_agent();
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
        .unwrap_or_else(|_| Config::default_agent());

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
