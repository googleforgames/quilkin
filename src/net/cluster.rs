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
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
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

/// Represents a full snapshot of all clusters.
#[derive(Default, Debug)]
pub struct ClusterMap {
    map: DashMap<Option<Locality>, BTreeSet<Endpoint>>,
    num_endpoints: AtomicUsize,
}

type DashMapRef<'inner> = dashmap::mapref::one::Ref<'inner, Option<Locality>, BTreeSet<Endpoint>>;

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
        if let Some(old) = self.map.insert(locality, cluster) {
            let old_len = old.len();
            if new_len >= old_len {
                self.num_endpoints.fetch_add(new_len - old_len, Relaxed);
            } else {
                self.num_endpoints.fetch_sub(old_len - new_len, Relaxed);
            }
            Some(old)
        } else {
            self.num_endpoints.fetch_add(new_len, Relaxed);
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
        self.remove_endpoint_if(|endpoint| endpoint.address == needle.address)
    }

    #[inline]
    pub fn remove_endpoint_if(&self, closure: impl Fn(&Endpoint) -> bool) -> bool {
        for mut entry in self.map.iter_mut() {
            let set = entry.value_mut();
            if let Some(endpoint) = set.iter().find(|endpoint| (closure)(endpoint)).cloned() {
                self.num_endpoints.fetch_sub(1, Relaxed);
                return set.remove(&endpoint);
            }
        }

        false
    }

    #[inline]
    pub fn replace(&self, locality: Option<Locality>, endpoint: Endpoint) -> Option<Endpoint> {
        if let Some(mut set) = self.map.get_mut(&locality) {
            let replaced = set.replace(endpoint);
            if replaced.is_none() {
                self.num_endpoints.fetch_add(1, Relaxed);
            }

            replaced
        } else {
            self.insert(locality, [endpoint].into());
            self.num_endpoints.fetch_add(1, Relaxed);
            None
        }
    }

    #[inline]
    pub fn iter(&self) -> dashmap::iter::Iter<Option<Locality>, BTreeSet<Endpoint>> {
        self.map.iter()
    }

    pub fn endpoints(&self) -> impl Iterator<Item = Endpoint> + '_ {
        self.map
            .iter()
            .flat_map(|entry| entry.value().iter().cloned().collect::<Vec<_>>())
    }

    pub fn nth_endpoint(&self, mut index: usize) -> Option<Endpoint> {
        for set in self.iter() {
            if index < set.len() {
                return set.value().iter().nth(index).cloned();
            } else {
                index -= set.len();
            }
        }

        None
    }

    pub fn filter_endpoints(&self, f: impl Fn(&Endpoint) -> bool) -> Vec<Endpoint> {
        let mut endpoints = Vec::new();

        for set in self.iter() {
            for endpoint in set.iter().filter(|e| (f)(e)) {
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

    pub fn update_unlocated_endpoints(&self, locality: Locality) {
        if let Some((_, set)) = self.map.remove(&None) {
            self.map.insert(Some(locality), set);
        }
    }
}

impl Clone for ClusterMap {
    fn clone(&self) -> Self {
        let map = self.map.clone();
        Self::from(map)
    }
}

impl PartialEq for ClusterMap {
    fn eq(&self, rhs: &Self) -> bool {
        for a in self.iter() {
            match rhs.get(a.key()).filter(|b| *a.value() == **b) {
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

impl<'de> Deserialize<'de> for ClusterMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec = Vec::<EndpointWithLocality>::deserialize(deserializer)?;
        if vec
            .iter()
            .map(|le| &le.locality)
            .collect::<BTreeSet<_>>()
            .len()
            != vec.len()
        {
            return Err(serde::de::Error::custom(
                "duplicate localities found in cluster map",
            ));
        }

        let map = DashMap::from_iter(vec.into_iter().map(
            |EndpointWithLocality {
                 locality,
                 endpoints,
             }| (locality, endpoints),
        ));

        Ok(Self::from(map))
    }
}

impl Serialize for ClusterMap {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.map
            .iter()
            .map(|entry| EndpointWithLocality::from((entry.key().clone(), entry.value().clone())))
            .collect::<Vec<_>>()
            .serialize(ser)
    }
}

impl From<DashMap<Option<Locality>, BTreeSet<Endpoint>>> for ClusterMap {
    fn from(map: DashMap<Option<Locality>, BTreeSet<Endpoint>>) -> Self {
        let num_endpoints = AtomicUsize::new(map.iter().map(|kv| kv.value().len()).sum());
        Self { map, num_endpoints }
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
