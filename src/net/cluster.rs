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

use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::net::endpoint::{Endpoint, Locality};

const SUBSYSTEM: &str = "cluster";

crate::include_proto!("quilkin.config.v1alpha1");
pub(crate) use self::quilkin::config::v1alpha1 as proto;

pub(crate) fn active_clusters() -> &'static prometheus::IntGauge {
    static ACTIVE_CLUSTERS: Lazy<prometheus::IntGauge> = Lazy::new(|| {
        crate::metrics::register(
            prometheus::IntGauge::with_opts(crate::metrics::opts(
                "active",
                SUBSYSTEM,
                "Number of currently active clusters.",
            ))
            .unwrap(),
        )
    });

    &ACTIVE_CLUSTERS
}

pub(crate) fn active_endpoints() -> &'static prometheus::IntGauge {
    static ACTIVE_ENDPOINTS: Lazy<prometheus::IntGauge> = Lazy::new(|| {
        crate::metrics::register(
            prometheus::IntGauge::with_opts(crate::metrics::opts(
                "active_endpoints",
                SUBSYSTEM,
                "Number of currently active endpoints.",
            ))
            .unwrap(),
        )
    });

    &ACTIVE_ENDPOINTS
}

#[derive(Debug, Clone)]
pub struct EndpointSet {
    pub endpoints: BTreeSet<Endpoint>,
    /// Version of this set of endpoints. Any mutatation of the endpoints
    /// set monotonically increases this number
    pub version: u64,
}

impl EndpointSet {
    #[inline]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    #[inline]
    pub fn contains(&self, ep: &Endpoint) -> bool {
        self.endpoints.contains(ep)
    }
}

/// Represents a full snapshot of all clusters.
#[derive(Default, Debug)]
pub struct ClusterMap {
    map: DashMap<Option<Locality>, EndpointSet>,
    num_endpoints: AtomicUsize,
    version: AtomicU64,
}

type DashMapRef<'inner> = dashmap::mapref::one::Ref<'inner, Option<Locality>, EndpointSet>;

impl ClusterMap {
    pub fn new_default(cluster: BTreeSet<Endpoint>) -> Self {
        let this = Self::default();
        this.insert_default(cluster);
        this
    }

    #[inline]
    pub fn insert(
        &self,
        locality: Option<Locality>,
        cluster: BTreeSet<Endpoint>,
    ) -> Option<BTreeSet<Endpoint>> {
        let new_len = cluster.len();
        if let Some(mut current) = self.map.get_mut(&locality) {
            let current = current.value_mut();

            let old = std::mem::replace(&mut current.endpoints, cluster);
            current.version += 1;

            let old_len = old.len();

            if new_len >= old_len {
                self.num_endpoints.fetch_add(new_len - old_len, Relaxed);
            } else {
                self.num_endpoints.fetch_sub(old_len - new_len, Relaxed);
            }

            self.version.fetch_add(1, Relaxed);
            Some(old)
        } else {
            self.map.insert(
                locality,
                EndpointSet {
                    endpoints: cluster,
                    version: 1,
                },
            );
            self.num_endpoints.fetch_add(new_len, Relaxed);
            self.version.fetch_add(1, Relaxed);
            None
        }
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
    pub fn get(&self, key: &Option<Locality>) -> Option<DashMapRef> {
        self.map.get(key)
    }

    #[inline]
    pub fn get_default(&self) -> Option<DashMapRef> {
        self.get(&None)
    }

    #[inline]
    pub fn insert_default(&self, endpoints: BTreeSet<Endpoint>) {
        self.insert(None, endpoints);
    }

    #[inline]
    pub fn remove_endpoint(&self, needle: &Endpoint) -> bool {
        for mut entry in self.map.iter_mut() {
            let set = entry.value_mut();

            if set.endpoints.remove(needle) {
                set.version += 1;
                self.num_endpoints.fetch_sub(1, Relaxed);
                self.version.fetch_add(1, Relaxed);
                return true;
            }
        }

        false
    }

    #[inline]
    pub fn remove_endpoint_if(&self, closure: impl Fn(&Endpoint) -> bool) -> bool {
        for mut entry in self.map.iter_mut() {
            let set = entry.value_mut();
            if let Some(endpoint) = set
                .endpoints
                .iter()
                .find(|endpoint| (closure)(endpoint))
                .cloned()
            {
                // This will always be true, but....
                let removed = set.endpoints.remove(&endpoint);
                if removed {
                    self.num_endpoints.fetch_sub(1, Relaxed);
                    self.version.fetch_add(1, Relaxed);
                    set.version += 1;
                }
                return removed;
            }
        }

        false
    }

    #[inline]
    pub fn replace(&self, locality: Option<Locality>, endpoint: Endpoint) -> Option<Endpoint> {
        if let Some(mut set) = self.map.get_mut(&locality) {
            let replaced = set.endpoints.replace(endpoint);
            set.version += 1;
            self.version.fetch_add(1, Relaxed);

            if replaced.is_none() {
                self.num_endpoints.fetch_add(1, Relaxed);
            }

            replaced
        } else {
            self.insert(locality, [endpoint].into());
            None
        }
    }

    #[inline]
    pub fn iter(&self) -> dashmap::iter::Iter<Option<Locality>, EndpointSet> {
        self.map.iter()
    }

    #[inline]
    pub fn endpoints(&self) -> Vec<Endpoint> {
        let mut endpoints = Vec::with_capacity(self.num_of_endpoints());

        for set in self.map.iter() {
            endpoints.extend(set.value().endpoints.iter().cloned());
        }

        endpoints
    }

    pub fn nth_endpoint(&self, mut index: usize) -> Option<Endpoint> {
        for set in self.iter() {
            let set = &set.value().endpoints;
            if index < set.len() {
                return set.iter().nth(index).cloned();
            } else {
                index -= set.len();
            }
        }

        None
    }

    pub fn filter_endpoints(&self, f: impl Fn(&Endpoint) -> bool) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        for set in self.iter() {
            for endpoint in set.endpoints.iter().filter(|e| (f)(e)) {
                endpoints.push(endpoint.clone());
            }
        }

        endpoints
    }

    #[inline]
    pub fn num_of_endpoints(&self) -> usize {
        self.num_endpoints.load(Relaxed)
    }

    #[inline]
    pub fn has_endpoints(&self) -> bool {
        self.num_of_endpoints() != 0
    }

    #[inline]
    pub fn version(&self) -> u64 {
        self.version.load(Relaxed)
    }

    pub fn update_unlocated_endpoints(&self, locality: Locality) {
        if let Some((_, set)) = self.map.remove(&None) {
            self.map.insert(Some(locality), set);
        }
    }
}

impl crate::config::watch::Watchable for ClusterMap {
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

impl Clone for ClusterMap {
    fn clone(&self) -> Self {
        let map = self.map.clone();
        Self::from(map)
    }
}

#[cfg(test)]
impl PartialEq for ClusterMap {
    fn eq(&self, rhs: &Self) -> bool {
        for a in self.iter() {
            match rhs
                .get(a.key())
                .filter(|b| a.value().endpoints == b.endpoints)
            {
                Some(_) => {}
                None => return false,
            }
        }

        true
    }
}

#[derive(Default, Debug, Deserialize, Serialize, PartialEq, Clone, Eq, schemars::JsonSchema)]
pub(crate) struct EndpointWithLocality {
    pub endpoints: BTreeSet<Endpoint>,
    pub locality: Option<Locality>,
}

impl From<(Option<Locality>, BTreeSet<Endpoint>)> for EndpointWithLocality {
    fn from((locality, endpoints): (Option<Locality>, BTreeSet<Endpoint>)) -> Self {
        Self {
            locality,
            endpoints,
        }
    }
}

impl schemars::JsonSchema for ClusterMap {
    fn schema_name() -> String {
        <Vec<EndpointWithLocality>>::schema_name()
    }
    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <Vec<EndpointWithLocality>>::json_schema(gen)
    }

    fn is_referenceable() -> bool {
        <Vec<EndpointWithLocality>>::is_referenceable()
    }
}

pub struct ClusterMapDeser {
    pub(crate) endpoints: Vec<EndpointWithLocality>,
}

impl<'de> Deserialize<'de> for ClusterMapDeser {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut endpoints = Vec::<EndpointWithLocality>::deserialize(deserializer)?;

        endpoints.sort_by(|a, b| a.locality.cmp(&b.locality));

        for window in endpoints.windows(2) {
            if window[0] == window[1] {
                return Err(serde::de::Error::custom(
                    "duplicate localities found in cluster map",
                ));
            }
        }

        Ok(Self { endpoints })
    }
}

impl<'de> Deserialize<'de> for ClusterMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cmd = ClusterMapDeser::deserialize(deserializer)?;
        Ok(Self::from(cmd))
    }
}

impl Serialize for ClusterMap {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.map
            .iter()
            .map(|entry| {
                EndpointWithLocality::from((entry.key().clone(), entry.value().endpoints.clone()))
            })
            .collect::<Vec<_>>()
            .serialize(ser)
    }
}

impl From<ClusterMapDeser> for ClusterMap {
    fn from(cmd: ClusterMapDeser) -> Self {
        let map = DashMap::from_iter(cmd.endpoints.into_iter().map(
            |EndpointWithLocality {
                 locality,
                 endpoints,
             }| {
                (
                    locality,
                    EndpointSet {
                        version: 0,
                        endpoints,
                    },
                )
            },
        ));

        Self::from(map)
    }
}

impl From<DashMap<Option<Locality>, EndpointSet>> for ClusterMap {
    fn from(map: DashMap<Option<Locality>, EndpointSet>) -> Self {
        let num_endpoints = AtomicUsize::new(map.iter().map(|kv| kv.value().len()).sum());
        Self {
            map,
            num_endpoints,
            version: AtomicU64::new(1),
        }
    }
}

impl From<(Option<Locality>, BTreeSet<Endpoint>)> for proto::Cluster {
    fn from((locality, endpoints): (Option<Locality>, BTreeSet<Endpoint>)) -> Self {
        Self {
            locality: locality.map(From::from),
            endpoints: endpoints.iter().map(From::from).collect(),
        }
    }
}

impl From<(&Option<Locality>, &BTreeSet<Endpoint>)> for proto::Cluster {
    fn from((locality, endpoints): (&Option<Locality>, &BTreeSet<Endpoint>)) -> Self {
        Self {
            locality: locality.clone().map(From::from),
            endpoints: endpoints.iter().map(From::from).collect(),
        }
    }
}

impl From<&'_ Endpoint> for proto::Endpoint {
    fn from(endpoint: &Endpoint) -> Self {
        Self {
            host: endpoint.address.host.to_string(),
            port: endpoint.address.port.into(),
            metadata: Some((&endpoint.metadata).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn merge() {
        let nl1 = Locality::region("nl-1");
        let de1 = Locality::region("de-1");

        let mut endpoint = Endpoint::new((Ipv4Addr::LOCALHOST, 7777).into());
        let cluster1 = ClusterMap::default();

        cluster1.insert(Some(nl1.clone()), [endpoint.clone()].into());
        cluster1.insert(Some(de1.clone()), [endpoint.clone()].into());

        assert_eq!(cluster1.get(&Some(nl1.clone())).unwrap().len(), 1);
        assert!(cluster1
            .get(&Some(nl1.clone()))
            .unwrap()
            .contains(&endpoint));
        assert_eq!(cluster1.get(&Some(de1.clone())).unwrap().len(), 1);
        assert!(cluster1
            .get(&Some(de1.clone()))
            .unwrap()
            .contains(&endpoint));

        endpoint.address.port = 8080;

        cluster1.insert(Some(de1.clone()), [endpoint.clone()].into());

        assert_eq!(cluster1.get(&Some(nl1.clone())).unwrap().len(), 1);
        assert_eq!(cluster1.get(&Some(de1.clone())).unwrap().len(), 1);
        assert!(cluster1
            .get(&Some(de1.clone()))
            .unwrap()
            .contains(&endpoint));

        cluster1.insert(Some(de1.clone()), <_>::default());

        assert_eq!(cluster1.get(&Some(nl1.clone())).unwrap().len(), 1);
        assert!(cluster1.get(&Some(de1.clone())).unwrap().is_empty());
    }
}
