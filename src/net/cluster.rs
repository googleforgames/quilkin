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
    collections::{hash_map::RandomState, BTreeSet},
    fmt,
};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::net::endpoint::{Endpoint, Locality};

const SUBSYSTEM: &str = "cluster";

crate::include_proto!("quilkin.config.v1alpha1");
pub use self::quilkin::config::v1alpha1 as proto;

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
#[derive(Clone)]
pub struct ClusterMap<S = RandomState>(DashMap<Option<Locality>, BTreeSet<Endpoint>, S>);

impl<S> fmt::Debug for ClusterMap<S>
where
    S: Default + std::hash::BuildHasher + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterMap")
            .field("map", &self.0)
            .finish_non_exhaustive()
    }
}

impl Default for ClusterMap<RandomState> {
    fn default() -> Self {
        Self(DashMap::new())
    }
}

impl ClusterMap<RandomState> {
    pub fn new_default(cluster: BTreeSet<Endpoint>) -> Self {
        let this = Self::default();
        this.insert_default(cluster);
        this
    }
}

type DashMapRef<'inner, S> =
    dashmap::mapref::one::Ref<'inner, Option<Locality>, BTreeSet<Endpoint>, S>;
type DashMapRefMut<'inner, S> =
    dashmap::mapref::one::RefMut<'inner, Option<Locality>, BTreeSet<Endpoint>, S>;

impl<S> ClusterMap<S>
where
    S: Default + std::hash::BuildHasher + Clone,
{
    pub fn benchmarking(capacity: usize, hasher: S) -> Self {
        Self(DashMap::with_capacity_and_hasher(capacity, hasher))
    }

    pub fn insert(
        &self,
        locality: Option<Locality>,
        cluster: BTreeSet<Endpoint>,
    ) -> Option<BTreeSet<Endpoint>> {
        self.0.insert(locality, cluster)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, key: &Option<Locality>) -> Option<DashMapRef<S>> {
        self.0.get(key)
    }

    pub fn get_mut(&self, key: &Option<Locality>) -> Option<DashMapRefMut<S>> {
        self.0.get_mut(key)
    }

    pub fn get_default(&self) -> Option<DashMapRef<S>> {
        self.get(&None)
    }

    pub fn get_default_mut(&self) -> Option<DashMapRefMut<S>> {
        self.get_mut(&None)
    }

    pub fn insert_default(&self, endpoints: BTreeSet<Endpoint>) {
        self.insert(None, endpoints);
    }

    pub fn remove_endpoint(&self, needle: &Endpoint) -> bool {
        self.remove_endpoint_if(|endpoint| endpoint.address == needle.address)
    }

    pub fn remove_endpoint_if(&self, closure: impl Fn(&Endpoint) -> bool) -> bool {
        for mut entry in self.0.iter_mut() {
            let set = entry.value_mut();
            if let Some(endpoint) = set.iter().find(|endpoint| (closure)(endpoint)).cloned() {
                return set.remove(&endpoint);
            }
        }

        false
    }

    pub fn iter(&self) -> dashmap::iter::Iter<Option<Locality>, BTreeSet<Endpoint>, S> {
        self.0.iter()
    }

    pub fn entry(
        &self,
        key: Option<Locality>,
    ) -> dashmap::mapref::entry::Entry<Option<Locality>, BTreeSet<Endpoint>, S> {
        self.0.entry(key)
    }

    pub fn default_entry(&self) -> DashMapRefMut<S> {
        self.entry(None).or_default()
    }

    pub fn endpoints(&self) -> impl Iterator<Item = Endpoint> + '_ {
        self.0
            .iter()
            .flat_map(|entry| entry.value().iter().cloned().collect::<Vec<_>>())
    }

    pub fn update_unlocated_endpoints(&self, locality: Locality) {
        if let Some((_, set)) = self.0.remove(&None) {
            self.0.insert(Some(locality), set);
        }
    }

    pub fn merge(&self, locality: Option<Locality>, endpoints: BTreeSet<Endpoint>) {
        if let Some(mut set) = self.get_mut(&locality) {
            *set = endpoints;
        } else {
            self.insert(locality, endpoints);
        }
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

        Ok(Self(DashMap::from_iter(vec.into_iter().map(
            |EndpointWithLocality {
                 locality,
                 endpoints,
             }| (locality, endpoints),
        ))))
    }
}

impl Serialize for ClusterMap {
    fn serialize<S>(&self, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0
            .iter()
            .map(|entry| EndpointWithLocality::from((entry.key().clone(), entry.value().clone())))
            .collect::<Vec<_>>()
            .serialize(ser)
    }
}

impl From<DashMap<Option<Locality>, BTreeSet<Endpoint>>> for ClusterMap {
    fn from(value: DashMap<Option<Locality>, BTreeSet<Endpoint>>) -> Self {
        Self(value)
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
        let nl1 = Locality::with_region("nl-1");
        let de1 = Locality::with_region("de-1");

        let mut endpoint = Endpoint::new((Ipv4Addr::LOCALHOST, 7777).into());
        let cluster1 = ClusterMap::default();

        cluster1.insert(Some(nl1.clone()), [endpoint.clone()].into());
        cluster1.merge(Some(de1.clone()), [endpoint.clone()].into());

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

        cluster1.merge(Some(de1.clone()), [endpoint.clone()].into());

        assert_eq!(cluster1.get(&Some(nl1.clone())).unwrap().len(), 1);
        assert_eq!(cluster1.get(&Some(de1.clone())).unwrap().len(), 1);
        assert!(cluster1
            .get(&Some(de1.clone()))
            .unwrap()
            .contains(&endpoint));

        cluster1.merge(Some(de1.clone()), <_>::default());

        assert_eq!(cluster1.get(&Some(nl1.clone())).unwrap().len(), 1);
        assert!(cluster1.get(&Some(de1.clone())).unwrap().is_empty());
    }
}
