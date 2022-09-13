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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::endpoint::{Endpoint, EndpointAddress, Locality, LocalityEndpoints};

const DEFAULT_CLUSTER_NAME: &str = "default";

#[derive(Clone, Default, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct Cluster {
    #[serde(skip, default = "default_cluster_name")]
    pub name: String,
    pub localities: LocalitySet,
}

impl Cluster {
    /// Creates a new `Cluster` called `name` containing `localities`.
    pub fn new(name: String, localities: impl Into<LocalitySet>) -> Self {
        Self {
            name,
            localities: localities.into(),
        }
    }

    /// Creates a new `Cluster` called `"default"` containing `endpoints`.
    pub fn new_default(endpoints: impl Into<LocalitySet>) -> Self {
        Self::new("default".into(), endpoints)
    }

    /// Adds a new set of endpoints to the cluster.
    pub fn insert(&mut self, endpoints: impl Into<LocalityEndpoints>) {
        self.localities.insert(endpoints.into());
    }

    /// Provides a flat iterator over the list of endpoints.
    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> + '_ {
        self.localities
            .iter()
            .flat_map(|locality| locality.endpoints.iter())
    }
}

fn default_cluster_name() -> String {
    DEFAULT_CLUSTER_NAME.into()
}

/// Represents a full snapshot of all clusters.
#[derive(Clone, Default, Debug, Serialize, PartialEq, Eq, JsonSchema)]
pub struct ClusterMap(HashMap<String, Cluster>);

impl ClusterMap {
    /// Creates a new `Cluster` called `name` containing `endpoints`.
    pub fn new_with_default_cluster(localities: impl Into<LocalityEndpoints>) -> Self {
        Self::from_iter([Cluster::new_default(vec![localities.into()])])
    }

    pub fn insert(&mut self, cluster: Cluster) -> Option<Cluster> {
        self.0.insert(cluster.name.clone(), cluster)
    }

    pub fn get(&self, key: &str) -> Option<&Cluster> {
        self.0.get(key)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Cluster> {
        self.0.get_mut(key)
    }

    pub fn get_default(&self) -> Option<&Cluster> {
        self.get(DEFAULT_CLUSTER_NAME)
    }

    pub fn get_default_mut(&mut self) -> Option<&mut Cluster> {
        self.get_mut(DEFAULT_CLUSTER_NAME)
    }

    pub fn insert_default(&mut self, cluster: impl Into<LocalityEndpoints>) {
        self.0.insert(
            DEFAULT_CLUSTER_NAME.into(),
            Cluster::new_default(vec![cluster.into()]),
        );
    }

    pub fn default_cluster_mut(&mut self) -> &mut Cluster {
        let entry = self.0.entry(DEFAULT_CLUSTER_NAME.into()).or_default();
        entry
            .name
            .is_empty()
            .then(|| entry.name = DEFAULT_CLUSTER_NAME.into());
        entry
    }

    pub fn localities(&self) -> impl Iterator<Item = &LocalityEndpoints> + '_ {
        self.0
            .values()
            .flat_map(|cluster| cluster.localities.iter())
    }

    pub fn endpoints(&self) -> impl Iterator<Item = Endpoint> + '_ {
        self.localities()
            .flat_map(|locality| locality.endpoints.clone())
    }

    pub fn contains_only_unique_endpoints(&self) -> bool {
        self.endpoints()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == self.endpoints().count()
    }
}

impl<'de> Deserialize<'de> for ClusterMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut map = HashMap::<String, Cluster>::deserialize(deserializer)?;

        for (key, value) in map.iter_mut() {
            value.name = key.clone();
        }

        Ok(Self(map))
    }
}

impl From<HashMap<String, Cluster>> for ClusterMap {
    fn from(value: HashMap<String, Cluster>) -> Self {
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

impl std::ops::Deref for ClusterMap {
    type Target = HashMap<String, Cluster>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for ClusterMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> From<[(String, Cluster); N]> for ClusterMap {
    fn from(value: [(String, Cluster); N]) -> Self {
        Self(value.into())
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

/// Set around [`LocalityEndpoints`] to ensure that all unique localities are
/// different entries. Any duplicate localities provided are merged.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct LocalitySet(HashMap<Option<Locality>, LocalityEndpoints>);

impl LocalitySet {
    /// Creates a new set from the provided localities.
    pub fn new(set: Vec<LocalityEndpoints>) -> Self {
        Self::from_iter(set)
    }

    /// Inserts a new locality of endpoints.
    pub fn insert(&mut self, mut locality: LocalityEndpoints) {
        self.0
            .entry(locality.locality)
            .or_default()
            .endpoints
            .append(&mut locality.endpoints);
    }

    /// Removes all localities.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Returns an iterator over the set of localities.
    pub fn iter(&self) -> impl Iterator<Item = &LocalityEndpoints> + '_ {
        self.0.values()
    }

    /// Returns a mutable iterator over the set of localities.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut LocalityEndpoints> + '_ {
        self.0.values_mut()
    }
}

impl Serialize for LocalitySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.values().collect::<Vec<_>>().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LocalitySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <Vec<LocalityEndpoints>>::deserialize(deserializer).map(Self::new)
    }
}

impl schemars::JsonSchema for LocalitySet {
    fn schema_name() -> String {
        <Vec<LocalityEndpoints>>::schema_name()
    }
    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <Vec<LocalityEndpoints>>::json_schema(gen)
    }

    fn is_referenceable() -> bool {
        <Vec<LocalityEndpoints>>::is_referenceable()
    }
}

impl<T> From<T> for LocalitySet
where
    T: Into<Vec<LocalityEndpoints>>,
{
    fn from(value: T) -> Self {
        Self::new(value.into())
    }
}

impl FromIterator<LocalityEndpoints> for LocalitySet {
    fn from_iter<I: IntoIterator<Item = LocalityEndpoints>>(iter: I) -> Self {
        let mut map = Self(<_>::default());

        for locality in iter {
            map.insert(locality);
        }

        map
    }
}

impl IntoIterator for LocalitySet {
    type Item = LocalityEndpoints;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        // Have to convert to vec to avoid `Values`'s lifetime parameter.
        // Remove once GAT's are stable.
        self.0.into_values().collect::<Vec<_>>().into_iter()
    }
}
