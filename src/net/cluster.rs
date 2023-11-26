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
    sync::atomic::{
        AtomicU64, AtomicUsize,
        Ordering::{self, Relaxed},
    },
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
    hash: AtomicU64,
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
        self.update_hash(&locality, &cluster, true);
        if let Some(old) = self.map.insert(locality.clone(), cluster) {
            let old_len = old.len();
            if new_len >= old_len {
                self.num_endpoints.fetch_add(new_len - old_len, Relaxed);
            } else {
                self.num_endpoints.fetch_sub(old_len - new_len, Relaxed);
            }
            self.update_hash(&locality, &old, false);
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

    pub fn remove(&self, locality: &Option<Locality>) {
        if let Some((_, value)) = self.map.remove(locality) {
            self.update_hash(locality, &value, false);
        }
    }

    pub fn contains(&self, locality: &Option<Locality>) -> bool {
        self.map.contains_key(locality)
    }

    #[inline]
    pub fn remove_endpoint_if(&self, closure: impl Fn(&Endpoint) -> bool) -> bool {
        for mut entry in self.map.iter_mut() {
            let key = entry.key().clone();
            let set = entry.value_mut();
            if let Some(endpoint) = set.iter().find(|endpoint| (closure)(endpoint)).cloned() {
                self.num_endpoints.fetch_sub(1, Relaxed);
                self.update_hash(&key, set, false);
                let removed = set.remove(&endpoint);
                self.update_hash(&key, set, true);
                return removed;
            }
        }

        false
    }

    #[inline]
    pub fn replace(&self, locality: Option<Locality>, endpoint: Endpoint) -> Option<Endpoint> {
        if let Some(mut set) = self.map.get_mut(&locality) {
            self.update_hash(&locality, &set, false);

            let replaced = set.replace(endpoint);
            if replaced.is_none() {
                self.num_endpoints.fetch_add(1, Relaxed);
            }

            self.update_hash(&locality, &set, true);

            replaced
        } else {
            let set = [endpoint].into();
            self.update_hash(&locality, &set, true);
            self.insert(locality, set);
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
            let key = Some(locality);
            self.update_hash(&None, &set, false);
            self.update_hash(&key, &set, true);
            self.map.insert(key, set);
        }
    }

    fn initial_hash(map: &DashMap<Option<Locality>, BTreeSet<Endpoint>>) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut hash = 0;
        for entry in map.iter() {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            (entry.key(), entry.value()).hash(&mut hasher);
            hash += hasher.finish();
        }
        hash
    }

    fn update_hash(&self, key: &Option<Locality>, value: &BTreeSet<Endpoint>, add: bool) {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (key, value).hash(&mut hasher);
        let item_hash = hasher.finish();

        self.hash
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current_hash| {
                Some(if add {
                    current_hash.wrapping_add(item_hash)
                } else {
                    current_hash.wrapping_sub(item_hash)
                })
            })
            .unwrap();
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
        self.hash.load(Ordering::SeqCst) == rhs.hash.load(Ordering::SeqCst)
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
        let hash = AtomicU64::from(Self::initial_hash(&map));
        Self {
            map,
            num_endpoints,
            hash,
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

    fn create_test_locality_and_endpoint() -> (Option<Locality>, BTreeSet<Endpoint>) {
        let nl1 = Locality::region("nl-1");
        let mut endpoints = BTreeSet::new();
        let endpoint = Endpoint::new((Ipv4Addr::LOCALHOST, 7777).into());
        endpoints.insert(endpoint);

        (Some(nl1), endpoints)
    }

    #[test]
    fn insert_affects_hash() {
        let map = ClusterMap::default();
        let initial_hash = map.hash.load(Ordering::SeqCst);
        let (locality, endpoints) = create_test_locality_and_endpoint();
        map.insert(locality, endpoints);
        assert_ne!(initial_hash, map.hash.load(Ordering::SeqCst));
    }

    #[test]
    fn remove_affects_hash() {
        let map = ClusterMap::default();
        let (locality, endpoints) = create_test_locality_and_endpoint();
        map.insert(locality.clone(), endpoints.clone());
        let hash_after_insert = map.hash.load(Ordering::SeqCst);
        map.remove_endpoint(endpoints.first().unwrap());
        assert_ne!(hash_after_insert, map.hash.load(Ordering::SeqCst));
    }

    #[test]
    fn same_data_equal_hashes() {
        let map1 = ClusterMap::default();
        let map2 = ClusterMap::default();
        let (locality1, endpoints1) = create_test_locality_and_endpoint();
        let (locality2, endpoints2) = create_test_locality_and_endpoint();
        map1.insert(locality1, endpoints1);
        map2.insert(locality2, endpoints2);
        assert_eq!(
            map1.hash.load(Ordering::SeqCst),
            map2.hash.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn different_data_different_hashes() {
        let map1 = ClusterMap::default();
        let map2 = ClusterMap::default();
        let (locality1, endpoints1) = create_test_locality_and_endpoint();
        let (locality2, endpoints2) = create_test_locality_and_endpoint();
        map1.insert(locality1, endpoints1);
        map2.insert(locality2, endpoints2);
        map2.insert(Some(Locality::region("de-1")), BTreeSet::new());
        assert_ne!(
            map1.hash.load(Ordering::SeqCst),
            map2.hash.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn removal_and_replace() {
        let map = ClusterMap::default();
        let (locality, endpoints) = create_test_locality_and_endpoint();
        map.insert(locality.clone(), endpoints.clone());
        let initial_hash = map.hash.load(Ordering::SeqCst);
        let endpoint = endpoints.first().unwrap().clone();
        map.remove_endpoint(&endpoint);
        map.replace(locality, endpoint);
        assert_eq!(initial_hash, map.hash.load(Ordering::SeqCst));
    }

    #[test]
    fn removal_and_insert() {
        let map = ClusterMap::default();
        let (locality, endpoints) = create_test_locality_and_endpoint();
        map.insert(locality.clone(), endpoints.clone());
        let initial_hash = map.hash.load(Ordering::SeqCst);
        map.remove(&locality);
        map.insert(locality, endpoints);
        assert_eq!(initial_hash, map.hash.load(Ordering::SeqCst));
    }

    #[test]
    fn empty_map_hash() {
        let map = ClusterMap::default();
        assert_eq!(map.hash.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn order_independence() {
        let map1 = ClusterMap::default();
        let map2 = ClusterMap::default();
        let (locality1, endpoints1) = create_test_locality_and_endpoint();
        let (locality2, endpoints2) = (Some(Locality::region("de-1")), BTreeSet::new());
        map1.insert(locality1.clone(), endpoints1.clone());
        map1.insert(locality2.clone(), endpoints2.clone());
        map2.insert(locality2, endpoints2);
        map2.insert(locality1, endpoints1);
        assert_eq!(
            map1.hash.load(Ordering::SeqCst),
            map2.hash.load(Ordering::SeqCst)
        );
    }
}
