/*
 * Copyright 2020 Google LLC All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

pub const ENDPOINT_METADATA_KEY_PREFIX: &str = "quilkin.dev";
pub const ENDPOINT_METADATA_TOKEN_KEY: &str = "endpoint.tokens";

// TODO Move endpoint.rs out of config/ into cluster/
use crate::cluster::Endpoint;
use std::sync::Arc;

#[derive(Debug)]
pub struct EmptyListError;

#[derive(Debug)]
pub struct AllEndpointsRemovedError;

#[derive(Debug)]
pub struct IndexOutOfRangeError;

/// Endpoints represents the set of all known upstream endpoints.
#[derive(Clone, Debug, PartialEq)]
pub struct Endpoints(Arc<Vec<Endpoint>>);

/// UpstreamEndpoints represents a set of endpoints.
/// This set is guaranteed to be non-empty - any operation that would
/// cause the set to be empty will return an error instead.
pub struct UpstreamEndpoints {
    /// All endpoints in the initial set - this list never
    /// changes after initialization.
    endpoints: Endpoints,
    /// A view into the current subset of endpoints in the original set.
    /// It contains indices into the initial set, to form the subset.
    /// If unset, the initial set is the current subset.
    subset: Option<Vec<usize>>,
}

impl Endpoints {
    /// Returns an [`Endpoints`] backed by the provided list of endpoints.
    pub fn new(endpoints: Vec<Endpoint>) -> Result<Self, EmptyListError> {
        if endpoints.is_empty() {
            Err(EmptyListError)
        } else {
            Ok(Self(Arc::new(endpoints)))
        }
    }
}

impl From<Endpoints> for UpstreamEndpoints {
    fn from(endpoints: Endpoints) -> Self {
        UpstreamEndpoints {
            endpoints,
            subset: None,
        }
    }
}

impl UpstreamEndpoints {
    /// Returns the number of endpoints in the backing set.
    pub fn size(&self) -> usize {
        self.subset
            .as_ref()
            .map(|subset| subset.len())
            .unwrap_or_else(|| self.endpoints.0.len())
    }

    /// Updates the current subset of endpoints to contain only the endpoint
    /// at the specified zero-indexed position.
    pub fn keep(&mut self, index: usize) -> Result<(), IndexOutOfRangeError> {
        if index >= self.size() {
            return Err(IndexOutOfRangeError);
        }

        match self.subset.as_mut() {
            Some(subset) => {
                let index = subset[index];
                subset.clear();
                subset.push(index);
            }
            None => {
                self.subset = Some(vec![index]);
            }
        }

        Ok(())
    }

    /// Updates the current subset of endpoints to contain only the endpoints
    /// which the predicate returned `true`.
    /// Returns an error if the predicate returns `false` for all endpoints.
    pub fn retain<F>(&mut self, predicate: F) -> Result<(), AllEndpointsRemovedError>
    where
        F: Fn(&Endpoint) -> bool,
    {
        match self.subset.as_mut() {
            Some(subset) => {
                let endpoints = &self.endpoints;
                let new_subset = subset
                    .iter()
                    .filter(|&&index| predicate(&endpoints.0[index]))
                    .copied()
                    .collect::<Vec<_>>();

                if new_subset.is_empty() {
                    return Err(AllEndpointsRemovedError);
                }

                *subset = new_subset;
            }
            None => {
                let new_subset = self
                    .endpoints
                    .0
                    .iter()
                    .enumerate()
                    .filter(|(_, ep)| predicate(ep))
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();

                if new_subset.is_empty() {
                    return Err(AllEndpointsRemovedError);
                }
                self.subset = Some(new_subset);
            }
        };

        Ok(())
    }

    /// Iterate over the endpoints in the current subset.
    pub fn iter(&self) -> UpstreamEndpointsIter {
        UpstreamEndpointsIter {
            collection: self,
            index: 0,
        }
    }
}

/// An Iterator over all endpoints in an [`UpstreamEndpoints`]
pub struct UpstreamEndpointsIter<'a> {
    collection: &'a UpstreamEndpoints,
    index: usize,
}

impl<'a> Iterator for UpstreamEndpointsIter<'a> {
    type Item = &'a Endpoint;

    fn next(&mut self) -> Option<Self::Item> {
        match &self.collection.subset {
            Some(subset) => {
                self.index += 1;
                subset
                    .get(self.index - 1)
                    .and_then(|&index| self.collection.endpoints.0.get(index))
            }
            None => {
                self.index += 1;
                self.collection.endpoints.0.get(self.index - 1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Endpoints;
    use crate::cluster::Endpoint;
    use crate::config::UpstreamEndpoints;

    fn ep(id: usize) -> Endpoint {
        Endpoint::from_address(format!("127.0.0.{}:8080", id).parse().unwrap())
    }

    #[test]
    fn new_endpoints() {
        assert!(Endpoints::new(vec![]).is_err());
        assert!(Endpoints::new(vec![ep(1)]).is_ok());
    }

    #[test]
    fn keep() {
        let initial_endpoints = vec![ep(1), ep(2), ep(3)];

        let mut up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();
        assert!(up.keep(initial_endpoints.len() - 1).is_ok());

        let mut up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();
        assert!(up.keep(initial_endpoints.len()).is_err());

        // Limit the set to only one element.
        let mut up = UpstreamEndpoints::from(Endpoints::new(initial_endpoints.clone()).unwrap());
        up.keep(1).unwrap();
        up.keep(0).unwrap();
        assert_eq!(vec![&initial_endpoints[1]], up.iter().collect::<Vec<_>>());

        let mut up = UpstreamEndpoints::from(Endpoints::new(initial_endpoints).unwrap());
        up.keep(1).unwrap();
        assert!(up.keep(1).is_err());
    }

    #[test]
    fn retain() {
        let initial_endpoints = vec![ep(1), ep(2), ep(3), ep(4)];

        let mut up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();

        up.retain(|ep| ep.address.to_string().as_str() != "127.0.0.2:8080")
            .unwrap();
        assert_eq!(up.size(), 3);
        assert_eq!(
            vec![ep(1), ep(3), ep(4)],
            up.iter().cloned().collect::<Vec<_>>()
        );

        up.retain(|ep| ep.address.to_string().as_str() != "127.0.0.3:8080")
            .unwrap();
        assert_eq!(up.size(), 2);
        assert_eq!(vec![ep(1), ep(4)], up.iter().cloned().collect::<Vec<_>>());

        // test an empty result on retain
        let result = up.retain(|_| false);
        assert!(result.is_err());

        let mut up: UpstreamEndpoints = Endpoints::new(initial_endpoints).unwrap().into();
        let result = up.retain(|_| false);
        assert!(result.is_err());
    }

    #[test]
    fn upstream_len() {
        let mut up: UpstreamEndpoints = Endpoints::new(vec![ep(1), ep(2), ep(3)]).unwrap().into();
        // starts out with all endpoints.
        assert_eq!(up.size(), 3);
        // verify that the set is now a singleton.
        up.keep(1).unwrap();
        assert_eq!(up.size(), 1);
    }

    #[test]
    fn upstream_all_iter() {
        let initial_endpoints = vec![ep(1), ep(2), ep(3)];
        let up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();

        let result = up.iter().cloned().collect::<Vec<_>>();
        assert_eq!(initial_endpoints, result);
    }

    #[test]
    fn upstream_some_iter() {
        let mut up = UpstreamEndpoints::from(Endpoints::new(vec![ep(1), ep(2), ep(3)]).unwrap());
        up.keep(1).unwrap();
        assert_eq!(vec![ep(2)], up.iter().cloned().collect::<Vec<_>>());
    }
}
