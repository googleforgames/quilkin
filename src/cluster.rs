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

mod metrics;
mod shared;

use std::collections::HashMap;

use crate::endpoint::Endpoint;

pub(crate) use shared::SharedCluster;

pub type ClusterLocalities = HashMap<Option<Locality>, LocalityEndpoints>;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Locality {
    pub region: String,
    pub zone: String,
    pub sub_zone: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalityEndpoints {
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cluster {
    pub localities: ClusterLocalities,
}

impl Cluster {
    pub fn new_static_cluster(endpoints: Vec<Endpoint>) -> Self {
        let endpoints = LocalityEndpoints { endpoints };

        Self {
            localities: [(None, endpoints)].into_iter().collect(),
        }
    }

    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> + '_ {
        self.localities.values().flat_map(|l| l.endpoints.iter())
    }
}

/// Represents a full snapshot the all clusters.
#[derive(Clone, Debug, Default)]
pub struct ClusterMap(HashMap<String, Cluster>);

impl ClusterMap {
    pub fn endpoints(&self) -> impl Iterator<Item = &Endpoint> + '_ {
        self.0.values().flat_map(|cluster| cluster.endpoints())
    }
}

impl From<HashMap<String, Cluster>> for ClusterMap {
    fn from(value: HashMap<String, Cluster>) -> Self {
        Self(value)
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
