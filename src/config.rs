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
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Duration,
};

use base64_serde::base64_serde_type;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    filters::{FilterChain, prelude::*},
    generated::envoy::service::discovery::v3::Resource as XdsResource,
    net::cluster::{self, ClusterMap},
    xds::{self, ResourceType},
};

pub use self::{
    config_type::ConfigType, error::ValidationError, providers::Providers, slot::Slot, watch::Watch,
};

mod config_type;
mod error;
pub mod providers;
pub mod providersv2;
mod serialization;
mod slot;
pub mod watch;

pub(crate) const BACKOFF_INITIAL_DELAY: Duration = Duration::from_millis(500);

pub type ConfigMap = typemap_rev::TypeMap<dyn typemap_rev::CloneDebuggableStorage>;

base64_serde_type!(pub Base64Standard, base64::engine::general_purpose::STANDARD);
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct Config {
    pub dyn_cfg: DynamicConfig,
}

#[cfg(test)]
impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Config;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("Quilkin config")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;

                let mut id = Option::<String>::None;
                let mut icao_code = None;
                let mut qcmp_port = None;
                let mut datacenters = None;
                let mut version = None;
                let mut typemap = default_typemap();

                macro_rules! tm_insert {
                    ($key:expr_2021, $field:expr_2021, $kind:ty) => {{
                        if $key == $field {
                            if typemap.contains_key::<$kind>() {
                                return Err(serde::de::Error::duplicate_field($field));
                            }

                            let value =
                                map.next_value::<<$kind as typemap_rev::TypeMapKey>::Value>()?;
                            typemap.insert::<$kind>(value);
                            continue;
                        }
                    }};
                }

                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    match key.as_ref() {
                        "id" => id = Some(map.next_value()?),
                        "datacenters" => {
                            if icao_code.is_some() || qcmp_port.is_some() {
                                return Err(Error::custom(
                                    "agent specific fields have already been deserialized",
                                ));
                            } else if datacenters.is_some() {
                                return Err(Error::duplicate_field("datacenters"));
                            }

                            datacenters = Some(map.next_value()?);
                        }
                        "icao_code" => {
                            if datacenters.is_some() {
                                return Err(Error::custom(
                                    "non-agent `datacenters` field has already been deserialized",
                                ));
                            } else if icao_code.is_some() {
                                return Err(Error::duplicate_field("icao_code"));
                            }

                            icao_code = Some(map.next_value()?);
                        }
                        "qcmp_port" => {
                            if datacenters.is_some() {
                                return Err(Error::custom(
                                    "non-agent `datacenters` field has already been deserialized",
                                ));
                            } else if qcmp_port.is_some() {
                                return Err(Error::duplicate_field("qcmp_port"));
                            }

                            qcmp_port = Some(map.next_value()?);
                        }
                        "version" => {
                            version = Some(map.next_value()?);
                        }
                        unknown => {
                            tm_insert!(key, "filters", FilterChain);
                            tm_insert!(key, "clusters", ClusterMap);

                            return Err(Error::unknown_field(
                                unknown,
                                &[
                                    "id",
                                    "filters",
                                    "clusters",
                                    "datacenters",
                                    "icao_code",
                                    "qcmp_port",
                                ],
                            ));
                        }
                    }
                }

                if let Some(datacenters) = datacenters {
                    typemap.insert::<DatacenterMap>(datacenters);
                } else if icao_code.is_none() && qcmp_port.is_none() {
                    typemap.insert::<DatacenterMap>(Default::default());
                } else {
                    typemap.insert::<Agent>(Agent {
                        icao_code: Slot::new(icao_code),
                        qcmp_port: Slot::new(qcmp_port),
                    });
                };

                Ok(Config {
                    dyn_cfg: DynamicConfig {
                        version: version.unwrap_or_default(),
                        id: id.map_or_else(default_id, Slot::new),
                        typemap,
                    },
                })
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

#[cfg(test)]
impl PartialEq for Config {
    fn eq(&self, other: &Self) -> bool {
        self.dyn_cfg == other.dyn_cfg
    }
}

#[derive(Clone, Debug, Default)]
pub struct Agent {
    pub icao_code: Slot<IcaoCode>,
    pub qcmp_port: Slot<u16>,
}

/// Configuration for a component
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub struct DynamicConfig {
    pub id: Slot<String>,
    pub version: Version,
    typemap: ConfigMap,
}

#[cfg(test)]
impl<'de> Deserialize<'de> for DynamicConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DynVisitor;

        impl<'de> serde::de::Visitor<'de> for DynVisitor {
            type Value = DynamicConfig;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("Quilkin dynamic config")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;

                let mut version = None;
                let mut id = None;
                let mut icao_code = None;
                let mut qcmp_port = None;
                let mut datacenters = None;
                let mut typemap = default_typemap();

                macro_rules! tm_insert {
                    ($key:expr_2021, $field:expr_2021, $kind:ty) => {{
                        if $key == $field {
                            if typemap.contains_key::<$kind>() {
                                return Err(serde::de::Error::duplicate_field($field));
                            }

                            let value =
                                map.next_value::<<$kind as typemap_rev::TypeMapKey>::Value>()?;
                            typemap.insert::<$kind>(value);
                            continue;
                        }
                    }};
                }

                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    let key = key.as_ref();
                    match key {
                        "id" => id = Some(map.next_value()?),
                        "version" => version = Some(map.next_value()?),
                        "datacenters" => {
                            if icao_code.is_some() || qcmp_port.is_some() {
                                return Err(Error::custom(
                                    "agent specific fields have already been deserialized",
                                ));
                            } else if datacenters.is_some() {
                                return Err(Error::duplicate_field("datacenters"));
                            }

                            datacenters = Some(map.next_value()?);
                        }
                        "icao_code" => {
                            if datacenters.is_some() {
                                return Err(Error::custom(
                                    "non-agent `datacenters` field has already been deserialized",
                                ));
                            } else if icao_code.is_some() {
                                return Err(Error::duplicate_field("icao_code"));
                            }

                            icao_code = Some(map.next_value()?);
                        }
                        "qcmp_port" => {
                            if datacenters.is_some() {
                                return Err(Error::custom(
                                    "non-agent `datacenters` field has already been deserialized",
                                ));
                            } else if qcmp_port.is_some() {
                                return Err(Error::duplicate_field("qcmp_port"));
                            }

                            qcmp_port = Some(map.next_value()?);
                        }
                        other => {
                            tm_insert!(key, "filters", FilterChain);
                            tm_insert!(key, "clusters", ClusterMap);

                            return Err(Error::unknown_field(other, &["id"]));
                        }
                    }
                }

                if let Some(datacenters) = datacenters {
                    typemap.insert::<DatacenterMap>(datacenters);
                } else if icao_code.is_none() && qcmp_port.is_none() {
                    typemap.insert::<DatacenterMap>(Default::default());
                } else {
                    typemap.insert::<Agent>(Agent {
                        icao_code: Slot::new(icao_code),
                        qcmp_port: Slot::new(qcmp_port),
                    });
                };

                Ok(DynamicConfig {
                    version: version.unwrap_or_default(),
                    id: id.map_or_else(default_id, |id| Slot::new(Some(id))),
                    typemap,
                })
            }
        }

        deserializer.deserialize_map(DynVisitor)
    }
}

impl typemap_rev::TypeMapKey for FilterChain {
    type Value = Slot<FilterChain>;
}

impl typemap_rev::TypeMapKey for ClusterMap {
    type Value = Watch<ClusterMap>;
}

impl typemap_rev::TypeMapKey for DatacenterMap {
    type Value = Watch<DatacenterMap>;
}

impl typemap_rev::TypeMapKey for Agent {
    type Value = Agent;
}

impl DynamicConfig {
    pub fn filters(&self) -> Option<&Slot<FilterChain>> {
        self.typemap.get::<FilterChain>()
    }

    pub fn clusters(&self) -> Option<&Watch<ClusterMap>> {
        self.typemap.get::<ClusterMap>()
    }

    pub fn datacenters(&self) -> Option<&Watch<DatacenterMap>> {
        self.typemap.get::<DatacenterMap>()
    }

    pub fn agent(&self) -> Option<&Agent> {
        self.typemap.get::<Agent>()
    }
}

#[cfg(test)]
impl PartialEq for DynamicConfig {
    fn eq(&self, other: &Self) -> bool {
        if self.id != other.id || self.version != other.version {
            return false;
        }

        fn compare<T>(a: &ConfigMap, b: &ConfigMap) -> bool
        where
            T: typemap_rev::TypeMapKey,
            T::Value: PartialEq + Clone + std::fmt::Debug,
        {
            let Some((a, b)) = a.get::<T>().zip(b.get::<T>()) else {
                return false;
            };
            a == b
        }

        compare::<FilterChain>(&self.typemap, &other.typemap)
            && compare::<ClusterMap>(&self.typemap, &other.typemap)
    }
}

impl quilkin_xds::config::Configuration for Config {
    fn identifier(&self) -> String {
        String::clone(&self.id())
    }

    fn allow_request_processing(&self, resource_type: &str) -> bool {
        resource_type.parse::<ResourceType>().is_ok()
    }

    fn apply_delta(
        &self,
        type_url: &str,
        resources: Vec<XdsResource>,
        removed_resources: &[String],
        remote_addr: Option<std::net::IpAddr>,
    ) -> quilkin_xds::Result<()> {
        self.apply_delta(type_url, resources, removed_resources, remote_addr)
    }

    fn delta_discovery_request(
        &self,
        client_state: &quilkin_xds::config::ClientState,
    ) -> quilkin_xds::Result<DeltaDiscoveryRes> {
        self.delta_discovery_request(client_state)
    }

    fn interested_resources(
        &self,
        _server_version: &str,
    ) -> impl Iterator<Item = (&'static str, Vec<String>)> {
        [
            (xds::CLUSTER_TYPE, Vec::new()),
            (xds::DATACENTER_TYPE, Vec::new()),
        ]
        .into_iter()
    }

    fn on_changed(
        &self,
        control_plane: quilkin_xds::server::ControlPlane<Self>,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        if let Some(fc) = control_plane
            .config
            .dyn_cfg
            .typemap
            .get::<FilterChain>()
            .filter(|_| !control_plane.is_relay)
        {
            fc.watch({
                let this = control_plane.clone();
                move |_| {
                    this.push_update(xds::FILTER_CHAIN_TYPE);
                }
            });
        }

        tracing::trace!("waiting for changes");

        async move {
            let clusters = control_plane.config.dyn_cfg.clusters();
            let datacenters = control_plane.config.dyn_cfg.datacenters();

            match (clusters, datacenters) {
                (Some(clusters), Some(dc)) => {
                    let mut cw = clusters.watch();
                    let mut dcw = dc.watch();
                    loop {
                        tokio::select! {
                            result = cw.changed() => {
                                match result {
                                    Ok(()) => control_plane.push_update(xds::CLUSTER_TYPE),
                                    Err(error) => tracing::error!(%error, "error watching changes"),
                                }
                            }
                            result = dcw.changed() => {
                                match result {
                                    Ok(()) => control_plane.push_update(xds::DATACENTER_TYPE),
                                    Err(error) => tracing::error!(%error, "error watching changes"),
                                }
                            }
                        }
                    }
                }
                (Some(clusters), None) => {
                    let mut cw = clusters.watch();

                    loop {
                        match cw.changed().await {
                            Ok(()) => control_plane.push_update(xds::CLUSTER_TYPE),
                            Err(error) => tracing::error!(%error, "error watching changes"),
                        }
                    }
                }
                (None, Some(dc)) => {
                    let mut dcw = dc.watch();

                    loop {
                        match dcw.changed().await {
                            Ok(()) => control_plane.push_update(xds::DATACENTER_TYPE),
                            Err(error) => tracing::error!(%error, "error watching changes"),
                        }
                    }
                }
                (None, None) => loop {
                    tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
                },
            }
        }
    }
}

use crate::net::xds::config::DeltaDiscoveryRes;

impl Config {
    /// Given a list of subscriptions and the current state of the calling client,
    /// construct a response with the current state of our resources that differ
    /// from those of the client
    pub fn delta_discovery_request(
        &self,
        client_state: &quilkin_xds::config::ClientState,
    ) -> crate::Result<DeltaDiscoveryRes> {
        let mut resources = Vec::new();
        let mut removed = std::collections::HashSet::new();

        let resource_type = client_state.resource_type.parse::<ResourceType>()?;

        'append: {
            match resource_type {
                ResourceType::FilterChain => {
                    let Some(filters) = self.dyn_cfg.filters() else {
                        break 'append;
                    };

                    let resource = xds::Resource::FilterChain(
                        crate::net::cluster::proto::FilterChain::try_from(&*filters.load())?,
                    );
                    let any = resource.try_encode()?;
                    let version = gxhash::gxhash64(&any.value, 0xdeadbeef);

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
                crate::xds::ResourceType::Listener => {
                    let Some(filters) = self.dyn_cfg.filters() else {
                        break 'append;
                    };

                    let resource = crate::xds::Resource::Listener(
                        crate::net::cluster::proto::FilterChain::try_from(&*filters.load())?,
                    );
                    let any = resource.try_encode()?;

                    resources.push(XdsResource {
                        name: "listener".into(),
                        version: "0".into(),
                        resource: Some(any),
                        aliases: Vec::new(),
                        ttl: None,
                        cache_control: None,
                    });
                }
                ResourceType::Datacenter => {
                    if let Some(agent) = self.dyn_cfg.agent() {
                        let name = agent.icao_code.load().to_string();
                        let qcmp_port = *agent.qcmp_port.load();
                        let port_s = qcmp_port.to_string();

                        if client_state.version_matches(&name, &port_s) {
                            break 'append;
                        }

                        let resource =
                            xds::Resource::Datacenter(crate::net::cluster::proto::Datacenter {
                                qcmp_port: qcmp_port as _,
                                icao_code: name.clone(),
                                ..Default::default()
                            });

                        resources.push(XdsResource {
                            name,
                            version: port_s,
                            resource: Some(resource.try_encode()?),
                            aliases: Vec::new(),
                            ttl: None,
                            cache_control: None,
                        });
                    } else if let Some(datacenters) = self.dyn_cfg.datacenters() {
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
                }
                ResourceType::Cluster => {
                    let mut push = |key: &Option<crate::net::endpoint::Locality>,
                                    value: &crate::net::cluster::EndpointSet|
                     -> crate::Result<()> {
                        let version = value.version().to_string();
                        let key_s = key.as_ref().map(|k| k.to_string()).unwrap_or_default();

                        if client_state.version_matches(&key_s, &version) {
                            return Ok(());
                        }

                        let resource = crate::xds::Resource::Cluster(
                            quilkin_xds::generated::quilkin::config::v1alpha1::Cluster {
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

                    let Some(clusters) = self.dyn_cfg.clusters() else {
                        break 'append;
                    };

                    if client_state.subscribed.is_empty() {
                        for cluster in clusters.read().iter() {
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
                            if let Some(cluster) = clusters.read().get(&locality) {
                                push(cluster.key(), cluster.value())?;
                            }
                        }
                    };

                    // Currently, we have exactly _one_ special case for removed resources, which
                    // is when ClusterMap::update_unlocated_endpoints is called to move the None
                    // locality endpoints to another one, so we just detect that case manually
                    if client_state.versions.contains_key("")
                        && clusters.read().get(&None).is_none()
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
        removed_resources: &[String],
        remote_addr: Option<std::net::IpAddr>,
    ) -> crate::Result<()> {
        let resource_type = type_url.parse::<ResourceType>()?;

        match resource_type {
            ResourceType::FilterChain | ResourceType::Listener => {
                let Some(filters) = self.dyn_cfg.filters() else {
                    return Ok(());
                };

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

                let resource = match crate::xds::Resource::try_decode(resource)? {
                    crate::xds::Resource::FilterChain(r) | crate::xds::Resource::Listener(r) => r,
                    res => {
                        eyre::bail!(
                            "filter chain response contained a {} resource payload",
                            res.type_url()
                        );
                    }
                };

                let fc =
                    crate::filters::FilterChain::try_create_fallible(resource.filters.into_iter())?;

                filters.store(Arc::new(fc));
            }
            ResourceType::Datacenter => {
                let Some(datacenters) = self.dyn_cfg.datacenters() else {
                    return Ok(());
                };

                datacenters.modify(|wg| {
                    if let Some(ip) = remote_addr.filter(|_| !removed_resources.is_empty()) {
                        wg.remove(ip);
                    }

                    for res in resources {
                        let Some(resource) = res.resource else {
                            eyre::bail!("a datacenter resource could not be applied because it didn't contain an actual payload");
                        };

                        let dc = match crate::xds::Resource::try_decode(resource) {
                            Ok(crate::xds::Resource::Datacenter(dc)) => dc,
                            Ok(other) => {
                                eyre::bail!("a datacenter resource could not be applied because the resource payload was '{}'", other.type_url());
                            }
                            Err(error) => {
                                return Err(error.wrap_err("a datacenter resource could not be applied because the resource payload could not be decoded"));
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
                            }
                            Err(error) => {
                                return Err(error.wrap_err("a datacenter resource could not be applied because the resource payload could not be parsed"));
                            }
                        }
                    }

                    Ok(())
                })?;
            }
            ResourceType::Cluster => {
                let Some(clusters) = self.dyn_cfg.clusters() else {
                    return Ok(());
                };

                clusters.modify(|guard| -> crate::Result<()> {
                    for removed in removed_resources {
                        let locality = if removed.is_empty() {
                            None
                        } else {
                            Some(removed.parse()?)
                        };
                        guard.remove_locality(remote_addr, &locality);
                    }

                    for res in resources {
                        let Some(resource) = res.resource else {
                            eyre::bail!("a cluster resource could not be applied because it didn't contain an actual payload");
                        };

                        let cluster = match crate::xds::Resource::try_decode(resource) {
                            Ok(crate::xds::Resource::Cluster(c)) => c,
                            Ok(other) => {
                                eyre::bail!("a cluster resource could not be applied because the resource payload was '{}'", other.type_url());
                            }
                            Err(error) => {
                                return Err(error.wrap_err("a cluster resource could not be applied because the resource payload could not be decoded"));
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
                                return Err(error.wrap_err("a cluster resource could not be applied because one or more endpoints could not be parsed"));
                            }
                        };

                        let endpoints = crate::config::cluster::EndpointSet::with_version(
                            endpoints,
                            parsed_version,
                        );

                        let locality = cluster.locality.map(crate::net::endpoint::Locality::from);

                        guard.apply(remote_addr, locality, endpoints);
                    }

                    Ok(())
                })?;

                self.apply_metrics();
            }
        }

        Ok(())
    }

    #[inline]
    pub fn apply_metrics(&self) {
        let Some(clusters) = self.dyn_cfg.clusters() else {
            return;
        };
        crate::metrics::apply_clusters(clusters);
    }

    pub fn default_agent() -> Self {
        let mut typemap = default_typemap();
        insert_default::<FilterChain>(&mut typemap);
        insert_default::<ClusterMap>(&mut typemap);
        insert_default::<Agent>(&mut typemap);

        Self {
            dyn_cfg: DynamicConfig {
                id: default_id(),
                version: Version::default(),
                typemap,
            },
        }
    }

    pub fn default_non_agent() -> Self {
        let mut typemap = default_typemap();
        insert_default::<FilterChain>(&mut typemap);
        insert_default::<ClusterMap>(&mut typemap);
        insert_default::<DatacenterMap>(&mut typemap);

        Self {
            dyn_cfg: DynamicConfig {
                id: default_id(),
                version: Version::default(),
                typemap,
            },
        }
    }

    #[inline]
    pub fn id(&self) -> String {
        String::clone(&self.dyn_cfg.id.load())
    }
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct DatacenterMap {
    map: dashmap::DashMap<IpAddr, Datacenter>,
    #[serde(skip)]
    removed: parking_lot::Mutex<Vec<SocketAddr>>,
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
    pub fn get(&self, key: &IpAddr) -> Option<dashmap::mapref::one::Ref<'_, IpAddr, Datacenter>> {
        self.map.get(key)
    }

    #[inline]
    pub fn iter(&self) -> dashmap::iter::Iter<'_, IpAddr, Datacenter> {
        self.map.iter()
    }

    #[inline]
    pub fn remove(&self, ip: IpAddr) {
        let mut lock = self.removed.lock();
        let mut version = 0;

        let Some((_k, v)) = self.map.remove(&ip) else {
            return;
        };

        lock.push((ip, v.qcmp_port).into());
        version += 1;

        self.version.fetch_add(version, Relaxed);
    }

    #[inline]
    pub fn removed(&self) -> Vec<SocketAddr> {
        std::mem::take(&mut self.removed.lock())
    }
}

impl Clone for DatacenterMap {
    fn clone(&self) -> Self {
        let map = self.map.clone();
        Self {
            map,
            version: <_>::default(),
            removed: Default::default(),
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
    fn json_schema(r#gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <std::collections::HashMap<IpAddr, Datacenter>>::json_schema(r#gen)
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

    fn json_schema(r#gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        let mut schema = r#gen.subschema_for::<String>();
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

pub(crate) fn default_id() -> Slot<String> {
    Slot::from(
        std::env::var("QUILKIN_SERVICE_ID")
            .or_else(|_| {
                cfg_if::cfg_if! {
                    if #[cfg(target_os = "linux")] {
                        sys_info::hostname()
                    } else {
                        eyre::bail!("no sys_info support")
                    }
                }
            })
            .unwrap_or_else(|_| Uuid::new_v4().as_hyphenated().to_string()),
    )
}

pub(crate) fn default_typemap() -> ConfigMap {
    typemap_rev::TypeMap::custom()
}

pub(crate) fn insert_default<T>(tm: &mut ConfigMap)
where
    T: typemap_rev::TypeMapKey,
    T::Value: Default + Clone + std::fmt::Debug,
{
    tm.insert::<T>(T::Value::default());
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
                    });
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
