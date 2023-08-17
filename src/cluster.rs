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

use std::collections::HashMap;

use dashmap::DashMap;
use once_cell::sync::Lazy;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::endpoint::{Endpoint, EndpointAddress, Locality, LocalityEndpoints, LocalitySet};

const DEFAULT_CLUSTER_NAME: &str = "default";
const SUBSYSTEM: &str = "cluster";

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

#[derive(Clone, Default, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Cluster {
    #[serde(skip, default = "default_cluster_name")]
    pub name: String,
    pub localities: LocalitySet,
}

impl Cluster {
    /// Creates a new `Cluster` called `name` containing `localities`.
    pub fn new(name: impl Into<String>, localities: impl Into<LocalitySet>) -> Self {
        Self {
            name: name.into(),
            localities: localities.into(),
        }
    }

    /// Creates a new `Cluster` called `"default"` containing `endpoints`.
    pub fn new_default(endpoints: impl Into<LocalitySet>) -> Self {
        Self::new("default", endpoints)
    }

    /// Adds a new set of endpoints to the cluster.
    pub fn insert(&mut self, endpoints: impl Into<LocalityEndpoints>) {
        self.localities.insert(endpoints.into());
    }

    pub fn update_locality(&mut self, locality: &Locality) {
        if let Some(endpoints) = self.localities.remove(&None) {
            self.localities
                .insert(endpoints.with_locality(locality.clone()));
        }
    }

    /// Provides a flat iterator over the list of endpoints.
    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> + '_ {
        self.localities
            .iter()
            .flat_map(|locality| locality.endpoints.iter())
    }

    pub fn merge(&mut self, cluster: &Self) {
        self.localities.merge(&cluster.localities);
    }
}

fn default_cluster_name() -> String {
    DEFAULT_CLUSTER_NAME.into()
}

/// Represents a full snapshot of all clusters.
#[derive(Clone, Default, Debug, Serialize)]
pub struct ClusterMap(DashMap<String, Cluster>);

type DashMapRef<'inner> = dashmap::mapref::one::Ref<'inner, String, Cluster>;
type DashMapRefMut<'inner> = dashmap::mapref::one::RefMut<'inner, String, Cluster>;

impl ClusterMap {
    /// Creates a new `Cluster` called `name` containing `endpoints`.
    pub fn new_with_default_cluster(localities: impl Into<LocalityEndpoints>) -> Self {
        Self::from_iter([Cluster::new_default(vec![localities.into()])])
    }

    pub fn insert(&self, cluster: Cluster) -> Option<Cluster> {
        self.0.insert(cluster.name.clone(), cluster)
    }

    pub fn get(&self, key: &str) -> Option<DashMapRef> {
        self.0.get(key)
    }

    pub fn get_mut(&self, key: &str) -> Option<DashMapRefMut> {
        self.0.get_mut(key)
    }

    pub fn get_default(&self) -> Option<DashMapRef> {
        self.get(DEFAULT_CLUSTER_NAME)
    }

    pub fn get_default_mut(&self) -> Option<DashMapRefMut> {
        self.get_mut(DEFAULT_CLUSTER_NAME)
    }

    pub fn remove_endpoint(&self, endpoint: &Endpoint) -> Option<()> {
        self.0.iter_mut().find_map(|mut cluster| {
            for le in cluster.localities.iter_mut() {
                if let Some(endpoint) = le
                    .endpoints
                    .iter()
                    .find(|rhs| endpoint.address == rhs.address)
                    .cloned()
                {
                    le.endpoints.remove(&endpoint);
                }
            }

            None
        })
    }

    pub fn remove_endpoint_if(&self, closure: impl Fn(&Endpoint) -> bool) -> Option<()> {
        self.0.iter_mut().find_map(|mut cluster| {
            cluster.localities.iter_mut().find_map(|le| {
                le.endpoints
                    .iter()
                    .find(|endpoint| (closure)(endpoint))
                    .cloned()
                    .and_then(|endpoint| le.endpoints.remove(&endpoint).then_some(()))
            })
        })
    }

    pub fn insert_default(&self, cluster: impl Into<LocalityEndpoints>) {
        self.0.insert(
            DEFAULT_CLUSTER_NAME.into(),
            Cluster::new_default(vec![cluster.into()]),
        );
    }

    pub fn iter(&self) -> dashmap::iter::Iter<String, Cluster> {
        self.0.iter()
    }

    pub fn entry(&self, key: String) -> dashmap::mapref::entry::Entry<String, Cluster> {
        self.0.entry(key)
    }

    pub fn default_entry(&self, key: String) -> DashMapRefMut {
        let mut entry = self.entry(key.clone()).or_default();
        entry.name.is_empty().then(|| entry.name = key);
        entry
    }

    pub fn default_cluster_mut(&self) -> DashMapRefMut {
        self.default_entry(DEFAULT_CLUSTER_NAME.into())
    }

    /// Updates the locality of any endpoints which have no locality in any
    /// clusters to `locality`.
    pub fn update_unlocated_endpoints(&self, locality: &Locality) {
        for mut entry in self.0.iter_mut() {
            entry.update_locality(locality);
        }
    }

    pub fn localities(&self) -> impl Iterator<Item = LocalityEndpoints> + '_ {
        self.0
            .iter()
            .flat_map(|entry| entry.value().localities.clone().into_iter())
    }

    pub fn endpoints(&self) -> impl Iterator<Item = Endpoint> + '_ {
        self.localities().flat_map(|locality| locality.endpoints)
    }

    pub fn merge(&self, map: Self) {
        for cluster in map.iter() {
            let span = tracing::info_span!("applied_cluster", cluster = cluster.name,);
            let _entered = span.enter();

            let cluster = cluster.value();
            self.default_entry(cluster.name.clone()).merge(cluster);
        }
    }

    pub fn contains_only_unique_endpoints(&self) -> bool {
        self.endpoints()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == self.endpoints().count()
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

impl schemars::JsonSchema for ClusterMap {
    fn schema_name() -> String {
        <HashMap<String, Cluster>>::schema_name()
    }
    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <HashMap<String, Cluster>>::json_schema(gen)
    }

    fn is_referenceable() -> bool {
        <HashMap<String, Cluster>>::is_referenceable()
    }
}

impl<'de> Deserialize<'de> for ClusterMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = DashMap::<String, Cluster>::deserialize(deserializer)?;

        for mut entry in map.iter_mut() {
            entry.name = entry.key().clone();
        }

        Ok(Self(map))
    }
}

impl From<DashMap<String, Cluster>> for ClusterMap {
    fn from(value: DashMap<String, Cluster>) -> Self {
        Self(value)
    }
}

impl From<Cluster> for ClusterMap {
    fn from(value: Cluster) -> Self {
        Self::from([value])
    }
}

impl<const N: usize> From<[Cluster; N]> for ClusterMap {
    fn from(value: [Cluster; N]) -> Self {
        Self::from_iter(value)
    }
}

impl FromIterator<Cluster> for ClusterMap {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Cluster>,
    {
        Self(
            iter.into_iter()
                .map(|cluster| (cluster.name.clone(), cluster))
                .collect(),
        )
    }
}

impl<const N: usize> From<[(String, Cluster); N]> for ClusterMap {
    fn from(value: [(String, Cluster); N]) -> Self {
        Self::from_iter(value)
    }
}

impl FromIterator<(String, Cluster)> for ClusterMap {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (String, Cluster)>,
    {
        Self(iter.into_iter().collect())
    }
}

impl From<Cluster> for crate::xds::config::endpoint::v3::ClusterLoadAssignment {
    fn from(cluster: Cluster) -> Self {
        Self {
            cluster_name: cluster.name,
            endpoints: cluster.localities.into_iter().map(From::from).collect(),
            ..Self::default()
        }
    }
}

impl From<&'_ Cluster> for crate::xds::config::cluster::v3::Cluster {
    fn from(cluster: &Cluster) -> Self {
        Self {
            name: cluster.name.clone(),
            load_assignment: Some(cluster.into()),
            ..Self::default()
        }
    }
}

impl From<&'_ Cluster> for crate::xds::config::endpoint::v3::ClusterLoadAssignment {
    fn from(cluster: &Cluster) -> Self {
        Self {
            cluster_name: cluster.name.clone(),
            endpoints: cluster.localities.iter().cloned().map(From::from).collect(),
            ..Self::default()
        }
    }
}

impl TryFrom<crate::xds::config::endpoint::v3::ClusterLoadAssignment> for Cluster {
    type Error = eyre::Error;

    fn try_from(
        mut cla: crate::xds::config::endpoint::v3::ClusterLoadAssignment,
    ) -> Result<Self, Self::Error> {
        use crate::xds::config::endpoint::v3::lb_endpoint;

        let localities = cla
            .endpoints
            .into_iter()
            .map(|locality| {
                let endpoints = locality
                    .lb_endpoints
                    .into_iter()
                    .map(|endpoint| {
                        let metadata = endpoint.metadata;
                        let endpoint = match endpoint.host_identifier {
                            Some(lb_endpoint::HostIdentifier::Endpoint(endpoint)) => Ok(endpoint),
                            Some(lb_endpoint::HostIdentifier::EndpointName(name_reference)) => {
                                match cla.named_endpoints.remove(&name_reference) {
                                    Some(endpoint) => Ok(endpoint),
                                    None => Err(eyre::eyre!(
                                        "no endpoint found name reference {}",
                                        name_reference
                                    )),
                                }
                            }
                            None => Err(eyre::eyre!("no host found for endpoint")),
                        }?;

                        // Extract the endpoint's address.
                        let address: EndpointAddress = endpoint
                            .address
                            .and_then(|address| address.address)
                            .ok_or_else(|| eyre::eyre!("No address provided."))?
                            .try_into()?;

                        let endpoint = Endpoint::with_metadata(
                            address,
                            metadata
                                .map(crate::metadata::MetadataView::try_from)
                                .transpose()?
                                .unwrap_or_default(),
                        );
                        Ok(endpoint)
                    })
                    .collect::<Result<_, eyre::Error>>()?;

                let locality = locality.locality.map(From::from);

                Ok(LocalityEndpoints::new(endpoints).with_locality(locality))
            })
            .collect::<Result<_, eyre::Error>>()?;

        Ok(Cluster {
            name: cla.cluster_name,
            localities,
        })
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

        let mut cluster1 = Cluster::new_default(vec![LocalityEndpoints::from((
            endpoint.clone(),
            nl1.clone(),
        ))]);

        let cluster2 = Cluster::new_default(vec![LocalityEndpoints::from((
            endpoint.clone(),
            de1.clone(),
        ))]);

        cluster1.merge(&cluster2);

        assert_eq!(cluster1.localities[&Some(nl1.clone())].endpoints.len(), 1);
        assert!(cluster1.localities[&Some(nl1.clone())]
            .endpoints
            .contains(&endpoint));
        assert_eq!(cluster1.localities[&Some(de1.clone())].endpoints.len(), 1);
        assert!(cluster1.localities[&Some(de1.clone())]
            .endpoints
            .contains(&endpoint));

        endpoint.address.port = 8080;
        let cluster3 = Cluster::new_default(vec![LocalityEndpoints::from((
            endpoint.clone(),
            de1.clone(),
        ))]);

        cluster1.merge(&cluster3);

        assert_eq!(cluster1.localities[&Some(nl1.clone())].endpoints.len(), 1);
        assert_eq!(cluster1.localities[&Some(de1.clone())].endpoints.len(), 1);
        assert!(cluster1.localities[&Some(de1.clone())]
            .endpoints
            .contains(&endpoint));

        let cluster4 = Cluster::new_default(vec![LocalityEndpoints {
            locality: Some(de1.clone()),
            endpoints: <_>::default(),
        }]);

        cluster1.merge(&cluster4);

        assert_eq!(cluster1.localities[&Some(nl1)].endpoints.len(), 1);
        assert!(cluster1.localities[&Some(de1)].endpoints.is_empty());
    }
}
