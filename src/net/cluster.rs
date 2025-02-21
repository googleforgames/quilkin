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
    fmt,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::net::endpoint::{Endpoint, EndpointAddress, Locality};

const SUBSYSTEM: &str = "cluster";
const HASH_SEED: i64 = 0xdeadbeef;

pub use crate::generated::quilkin::config::v1alpha1 as proto;

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

pub type TokenAddressMap = gxhash::HashMap<u64, gxhash::HashSet<EndpointAddress>>;

#[derive(Copy, Clone)]
pub struct Token(u64);

impl Token {
    #[inline]
    pub fn new(token: &[u8]) -> Self {
        Self(gxhash::gxhash64(token, HASH_SEED))
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct EndpointSetVersion(u64);

impl EndpointSetVersion {
    pub fn from_number(version: u64) -> Self {
        Self(version)
    }

    pub fn number(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for EndpointSetVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::Debug for EndpointSetVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl std::str::FromStr for EndpointSetVersion {
    type Err = eyre::Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(u64::from_str_radix(s, 16)?))
    }
}

#[derive(Debug, Clone)]
pub struct EndpointSet {
    pub endpoints: BTreeSet<Endpoint>,
    pub token_map: TokenAddressMap,
    /// The hash of all of the endpoints in this set
    hash: u64,
    /// Version of this set of endpoints. Any mutatation of the endpoints
    /// set monotonically increases this number
    version: u64,
}

impl EndpointSet {
    /// Creates a new endpoint set, calculating a unique version hash for it
    #[inline]
    pub fn new(endpoints: BTreeSet<Endpoint>) -> Self {
        let mut this = Self {
            endpoints,
            token_map: <_>::default(),
            hash: 0,
            version: 0,
        };

        this.update();
        this
    }

    /// Creates a new endpoint set with the provided version hash, skipping
    /// calculation of it
    ///
    /// This hash _must_ be calculated with [`Self::update`] to be consistent
    /// across machines
    #[inline]
    pub fn with_version(endpoints: BTreeSet<Endpoint>, hash: EndpointSetVersion) -> Self {
        let mut this = Self {
            endpoints,
            token_map: <_>::default(),
            hash: hash.number(),
            version: 1,
        };

        this.build_token_map();
        this
    }

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

    /// Unique version for this endpoint set
    #[inline]
    pub fn version(&self) -> EndpointSetVersion {
        EndpointSetVersion::from_number(self.hash)
    }

    /// Bumps the version, calculating a hash for the entire endpoint set
    ///
    /// This is extremely expensive
    #[inline]
    pub fn update(&mut self) -> TokenAddressMap {
        use std::hash::{Hash, Hasher};
        let mut hasher = gxhash::GxHasher::with_seed(HASH_SEED);
        let mut token_map = TokenAddressMap::default();

        for ep in &self.endpoints {
            ep.hash(&mut hasher);

            for tok in &ep.metadata.known.tokens {
                let hash = gxhash::gxhash64(tok, HASH_SEED);
                token_map
                    .entry(hash)
                    .or_default()
                    .insert(ep.address.clone());
            }
        }

        self.hash = hasher.finish();
        self.version += 1;
        std::mem::replace(&mut self.token_map, token_map)
    }

    /// Creates a map of tokens -> address for the current set
    #[inline]
    pub fn build_token_map(&mut self) -> TokenAddressMap {
        let mut token_map = TokenAddressMap::default();

        // This is only called on proxies, so calculate a token map
        for ep in &self.endpoints {
            for tok in &ep.metadata.known.tokens {
                let hash = gxhash::gxhash64(tok, HASH_SEED);
                token_map
                    .entry(hash)
                    .or_default()
                    .insert(ep.address.clone());
            }
        }

        std::mem::replace(&mut self.token_map, token_map)
    }

    #[inline]
    pub fn replace(
        &mut self,
        replacement: Self,
    ) -> (
        usize,
        std::collections::HashMap<u64, Option<Vec<EndpointAddress>>>,
    ) {
        let old_len = std::mem::replace(&mut self.endpoints, replacement.endpoints).len();

        let old_tm = if replacement.hash == 0 {
            self.update()
        } else {
            self.hash = replacement.hash;
            self.version += 1;
            self.build_token_map()
        };

        let mut hm = std::collections::HashMap::new();

        for (token, addrs) in &old_tm {
            match self.token_map.get(token) {
                Some(naddrs) => {
                    if addrs.symmetric_difference(naddrs).count() > 0 {
                        hm.insert(*token, Some(naddrs.iter().cloned().collect()));
                    }
                }
                _ => {
                    hm.insert(*token, None);
                }
            }
        }

        for (token, addrs) in &self.token_map {
            if !hm.contains_key(token) {
                hm.insert(*token, Some(addrs.iter().cloned().collect()));
            }
        }

        (old_len, hm)
    }
}

/// Represents a full snapshot of all clusters.
pub struct ClusterMap<S = gxhash::GxBuildHasher> {
    map: DashMap<Option<Locality>, EndpointSet, S>,
    token_map: DashMap<u64, Vec<EndpointAddress>>,
    num_endpoints: AtomicUsize,
    version: AtomicU64,
}

type DashMapRef<'inner> = dashmap::mapref::one::Ref<'inner, Option<Locality>, EndpointSet>;
type DashMapRefMut<'inner> = dashmap::mapref::one::RefMut<'inner, Option<Locality>, EndpointSet>;

impl ClusterMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_default(cluster: BTreeSet<Endpoint>) -> Self {
        let this = Self::default();
        this.insert_default(cluster);
        this
    }
}

impl<S> ClusterMap<S> {
    #[inline]
    pub fn version(&self) -> u64 {
        self.version.load(Relaxed)
    }
}

impl<S> ClusterMap<S>
where
    S: Default + std::hash::BuildHasher + Clone,
{
    pub fn benchmarking(capacity: usize, hasher: S) -> Self {
        Self {
            map: DashMap::with_capacity_and_hasher(capacity, hasher),
            ..Self::default()
        }
    }

    #[inline]
    pub fn insert(&self, locality: Option<Locality>, cluster: BTreeSet<Endpoint>) {
        self.apply(locality, EndpointSet::new(cluster))
    }

    pub fn apply(&self, locality: Option<Locality>, cluster: EndpointSet) {
        let new_len = cluster.len();
        match self.map.get_mut(&locality) {
            Some(mut current) => {
                let current = current.value_mut();

                let (old_len, token_map_diff) = current.replace(cluster);

                if new_len >= old_len {
                    self.num_endpoints.fetch_add(new_len - old_len, Relaxed);
                } else {
                    self.num_endpoints.fetch_sub(old_len - new_len, Relaxed);
                }

                self.version.fetch_add(1, Relaxed);

                for (token_hash, addrs) in token_map_diff {
                    if let Some(addrs) = addrs {
                        self.token_map.insert(token_hash, addrs);
                    } else {
                        self.token_map.remove(&token_hash);
                    }
                }
            }
            _ => {
                for (token_hash, addrs) in &cluster.token_map {
                    self.token_map
                        .insert(*token_hash, addrs.iter().cloned().collect());
                }

                self.map.insert(locality, cluster);
                self.num_endpoints.fetch_add(new_len, Relaxed);
                self.version.fetch_add(1, Relaxed);
            }
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

    pub fn get(&self, key: &Option<Locality>) -> Option<DashMapRef> {
        self.map.get(key)
    }

    pub fn get_mut(&self, key: &Option<Locality>) -> Option<DashMapRefMut> {
        self.map.get_mut(key)
    }

    pub fn get_default(&self) -> Option<DashMapRef> {
        self.get(&None)
    }

    pub fn get_default_mut(&self) -> Option<DashMapRefMut> {
        self.get_mut(&None)
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
                set.update();
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
                    set.update();
                    self.num_endpoints.fetch_sub(1, Relaxed);
                    self.version.fetch_add(1, Relaxed);
                }
                return removed;
            }
        }

        false
    }

    #[inline]
    pub fn iter(&self) -> dashmap::iter::Iter<Option<Locality>, EndpointSet, S> {
        self.map.iter()
    }

    pub fn entry(
        &self,
        key: Option<Locality>,
    ) -> dashmap::mapref::entry::Entry<Option<Locality>, EndpointSet> {
        self.map.entry(key)
    }

    #[inline]
    pub fn replace(&self, locality: Option<Locality>, endpoint: Endpoint) -> Option<Endpoint> {
        match self.map.get_mut(&locality) {
            Some(mut set) => {
                let replaced = set.endpoints.replace(endpoint);
                set.update();
                self.version.fetch_add(1, Relaxed);

                if replaced.is_none() {
                    self.num_endpoints.fetch_add(1, Relaxed);
                }

                replaced
            }
            _ => {
                self.insert(locality, [endpoint].into());
                None
            }
        }
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
    pub fn update_unlocated_endpoints(&self, locality: Locality) {
        if let Some((_, set)) = self.map.remove(&None) {
            self.version.fetch_add(1, Relaxed);
            if let Some(replaced) = self.map.insert(Some(locality), set) {
                self.num_endpoints.fetch_sub(replaced.len(), Relaxed);
            }
        }
    }

    #[inline]
    pub fn remove_locality(&self, locality: &Option<Locality>) -> Option<EndpointSet> {
        let ret = self.map.remove(locality).map(|(_k, v)| v);
        if let Some(ret) = &ret {
            self.version.fetch_add(1, Relaxed);
            self.num_endpoints.fetch_sub(ret.len(), Relaxed);
        }

        ret
    }

    pub fn addresses_for_token(&self, token: Token, addrs: &mut Vec<EndpointAddress>) {
        if let Some(ma) = self.token_map.get(&token.0) {
            addrs.extend(ma.value().iter().cloned());
        }
    }
}

impl<S> crate::config::watch::Watchable for ClusterMap<S> {
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

impl<S> fmt::Debug for ClusterMap<S>
where
    S: Default + std::hash::BuildHasher + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterMap")
            .field("map", &self.map)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl<S> Default for ClusterMap<S>
where
    S: Default + std::hash::BuildHasher + Clone,
{
    fn default() -> Self {
        Self {
            map: <DashMap<Option<Locality>, EndpointSet, S>>::default(),
            token_map: Default::default(),
            version: <_>::default(),
            num_endpoints: <_>::default(),
        }
    }
}

impl Clone for ClusterMap {
    fn clone(&self) -> Self {
        let map = self.map.clone();
        Self::from(map)
    }
}

#[cfg(test)]
impl<S> PartialEq for ClusterMap<S>
where
    S: Default + std::hash::BuildHasher + Clone,
{
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
    fn json_schema(r#gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <Vec<EndpointWithLocality>>::json_schema(r#gen)
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

impl<S> From<ClusterMapDeser> for ClusterMap<S>
where
    S: Default + std::hash::BuildHasher + Clone,
{
    fn from(cmd: ClusterMapDeser) -> Self {
        let map = DashMap::from_iter(cmd.endpoints.into_iter().map(
            |EndpointWithLocality {
                 locality,
                 endpoints,
             }| { (locality, EndpointSet::new(endpoints)) },
        ));

        Self::from(map)
    }
}

impl<S> From<DashMap<Option<Locality>, EndpointSet, S>> for ClusterMap<S>
where
    S: Default + std::hash::BuildHasher + Clone,
{
    fn from(map: DashMap<Option<Locality>, EndpointSet, S>) -> Self {
        let num_endpoints = AtomicUsize::new(map.iter().map(|kv| kv.value().len()).sum());

        let token_map = DashMap::<u64, Vec<EndpointAddress>>::default();
        for es in &map {
            for (token_hash, addrs) in &es.value().token_map {
                token_map.insert(*token_hash, addrs.iter().cloned().collect());
            }
        }

        Self {
            map,
            token_map,
            num_endpoints,
            version: AtomicU64::new(1),
        }
    }
}

impl From<&'_ Endpoint> for proto::Endpoint {
    fn from(endpoint: &Endpoint) -> Self {
        Self {
            host: endpoint.address.host.to_string(),
            port: endpoint.address.port.into(),
            metadata: Some((&endpoint.metadata).into()),
            host2: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn merge() {
        let nl1 = Locality::with_region("nl-1");
        let de1 = Locality::with_region("de-1");

        let mut endpoint = Endpoint::new((Ipv4Addr::LOCALHOST, 7777).into());
        let cluster1 = ClusterMap::new();

        cluster1.insert(Some(nl1.clone()), [endpoint.clone()].into());
        cluster1.insert(Some(de1.clone()), [endpoint.clone()].into());

        assert_eq!(cluster1.get(&Some(nl1.clone())).unwrap().len(), 1);
        assert!(
            cluster1
                .get(&Some(nl1.clone()))
                .unwrap()
                .contains(&endpoint)
        );
        assert_eq!(cluster1.get(&Some(de1.clone())).unwrap().len(), 1);
        assert!(
            cluster1
                .get(&Some(de1.clone()))
                .unwrap()
                .contains(&endpoint)
        );

        endpoint.address.port = 8080;

        cluster1.insert(Some(de1.clone()), [endpoint.clone()].into());

        assert_eq!(cluster1.get(&Some(nl1.clone())).unwrap().len(), 1);
        assert_eq!(cluster1.get(&Some(de1.clone())).unwrap().len(), 1);
        assert!(
            cluster1
                .get(&Some(de1.clone()))
                .unwrap()
                .contains(&endpoint)
        );

        cluster1.insert(Some(de1.clone()), <_>::default());

        assert_eq!(cluster1.get(&Some(nl1.clone())).unwrap().len(), 1);
        assert!(cluster1.get(&Some(de1.clone())).unwrap().is_empty());
    }
}
