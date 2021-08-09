/*
 * Copyright 2021 Google LLC
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

//! Types representing where the data is the sent.

use std::{net::SocketAddr, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::metadata::Metadata;

/// Represents the set of all known upstream endpoints.
#[derive(Clone, Debug, PartialEq)]
pub struct Endpoints(Arc<Vec<Endpoint>>);

/// A destination endpoint with any associated metadata.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, PartialOrd, Eq)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub address: SocketAddr,
    #[serde(default)]
    pub metadata: Metadata<EndpointMetadata>,
}

impl Endpoint {
    /// Creates a new [`Endpoint`] with no metadata.
    pub fn new(address: SocketAddr) -> Self {
        Self::with_metadata(address, Metadata::default())
    }

    /// Creates a new [`Endpoint`] with the specified `metadata`.
    pub fn with_metadata(
        address: SocketAddr,
        metadata: impl Into<Metadata<EndpointMetadata>>,
    ) -> Self {
        Self {
            address,
            metadata: metadata.into(),
        }
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            address: std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0).into(),
            metadata: <_>::default(),
        }
    }
}

/// Metadata specific to endpoints.
#[derive(Default, Debug, Deserialize, Serialize, PartialEq, Clone, PartialOrd, Eq)]
#[non_exhaustive]
pub struct EndpointMetadata {
    #[serde(with = "base64_set")]
    pub tokens: base64_set::Set,
}

mod base64_set {
    use serde::de::Error;

    pub type Set<T = Vec<u8>> = std::collections::BTreeSet<T>;

    pub fn serialize<S>(set: &Set, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&set.iter().map(base64::encode).collect::<Vec<_>>(), ser)
    }

    pub fn deserialize<'de, D>(de: D) -> Result<Set, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let items = <Vec<String> as serde::Deserialize>::deserialize(de)?;
        let set = items.iter().cloned().collect::<Set<String>>();

        if set.len() != items.len() {
            Err(D::Error::custom(
                "Found duplicate tokens in endpoint metadata.",
            ))
        } else {
            set.into_iter()
                .map(|string| base64::decode(string).map_err(D::Error::custom))
                .collect()
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum MetadataError {
    #[error("Invalid bas64 encoded token: `{0}`.")]
    InvalidBase64(base64::DecodeError),
    #[error("Missing required key `{0}`.")]
    MissingKey(&'static str),
    #[error("Invalid type ({expected}) given for `{key}`.")]
    InvalidType {
        key: &'static str,
        expected: &'static str,
    },
}

impl std::convert::TryFrom<prost_types::Struct> for EndpointMetadata {
    type Error = MetadataError;

    fn try_from(mut value: prost_types::Struct) -> Result<Self, Self::Error> {
        use prost_types::value::Kind;
        const TOKENS: &str = "tokens";

        let tokens = if let Some(kind) = value.fields.remove(TOKENS).and_then(|v| v.kind) {
            if let Kind::ListValue(list) = kind {
                list.values
                    .into_iter()
                    .filter_map(|v| v.kind)
                    .map(|kind| {
                        if let Kind::StringValue(string) = kind {
                            base64::decode(string).map_err(MetadataError::InvalidBase64)
                        } else {
                            Err(MetadataError::InvalidType {
                                key: TOKENS,
                                expected: "base64 string",
                            })
                        }
                    })
                    .collect::<Result<_, _>>()?
            } else {
                return Err(MetadataError::MissingKey(TOKENS));
            }
        } else {
            <_>::default()
        };

        Ok(Self { tokens })
    }
}

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
    pub fn new(endpoints: Vec<Endpoint>) -> Option<Self> {
        (!endpoints.is_empty()).then(|| Self(Arc::new(endpoints)))
    }
}

/// Provides a read-only view into the underlying endpoints.
impl AsRef<Vec<Endpoint>> for Endpoints {
    fn as_ref(&self) -> &Vec<Endpoint> {
        self.0.as_ref()
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
    /// at the specified zero-indexed position, returns `None` if `index`
    /// is greater than the number of endpoints.
    pub fn keep(&mut self, index: usize) -> Option<()> {
        if index >= self.size() {
            return None;
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

        Some(())
    }

    /// Updates the current subset of endpoints to contain only the endpoints
    /// which the predicate returned `true`.
    /// Returns an error if the predicate returns `false` for all endpoints.
    pub fn retain<F>(&mut self, predicate: F) -> RetainedItems
    where
        F: Fn(&Endpoint) -> bool,
    {
        let endpoints = self
            .subset
            .as_ref()
            .map(|s| either::Right(s.iter().map(|&index| (index, &self.endpoints.0[index]))))
            .unwrap_or_else(|| either::Left(self.endpoints.0.iter().enumerate()));

        let total_items = endpoints.clone().count();
        let new_subset = endpoints
            .filter(|(_, ep)| predicate(ep))
            .map(|(i, _)| i)
            .collect::<Vec<_>>();

        if new_subset.is_empty() {
            return RetainedItems::None;
        }

        let retained_items = new_subset.len();
        self.subset = Some(new_subset);

        if retained_items == total_items {
            RetainedItems::All
        } else {
            RetainedItems::Some(retained_items)
        }
    }

    /// Iterate over the endpoints in the current subset.
    pub fn iter(&self) -> UpstreamEndpointsIter {
        UpstreamEndpointsIter {
            collection: self,
            index: 0,
        }
    }
}

/// An enum representing the result of a [`UpstreamEndpoints::retain`] call,
/// detailing how many (if any) of the endpoints were retained by the predicate.
#[non_exhaustive]
#[must_use]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RetainedItems {
    None,
    Some(usize),
    All,
}

impl RetainedItems {
    /// Returns whether `self` is [`RetainedItems::None`].
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns whether `self` is [`RetainedItems::All`].
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    /// Returns whether `self` is [`RetainedItems::Some`].
    pub fn is_some(&self) -> bool {
        matches!(self, Self::Some(_))
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
    use super::*;

    fn ep(id: usize) -> Endpoint {
        Endpoint::new(format!("127.0.0.{}:8080", id).parse().unwrap())
    }

    #[test]
    fn new_endpoints() {
        assert!(Endpoints::new(vec![]).is_none());
        assert!(Endpoints::new(vec![ep(1)]).is_some());
    }

    #[test]
    fn keep() {
        let initial_endpoints = vec![ep(1), ep(2), ep(3)];

        let mut up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();
        assert!(up.keep(initial_endpoints.len() - 1).is_some());

        let mut up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();
        assert!(up.keep(initial_endpoints.len()).is_none());

        // Limit the set to only one element.
        let mut up = UpstreamEndpoints::from(Endpoints::new(initial_endpoints.clone()).unwrap());
        up.keep(1).unwrap();
        up.keep(0).unwrap();
        assert_eq!(vec![&initial_endpoints[1]], up.iter().collect::<Vec<_>>());

        let mut up = UpstreamEndpoints::from(Endpoints::new(initial_endpoints).unwrap());
        up.keep(1).unwrap();
        assert!(up.keep(1).is_none());
    }

    #[test]
    fn retain() {
        let initial_endpoints = vec![ep(1), ep(2), ep(3), ep(4)];

        let mut up: UpstreamEndpoints = Endpoints::new(initial_endpoints.clone()).unwrap().into();

        let items = up.retain(|ep| ep.address.to_string().as_str() != "127.0.0.2:8080");
        assert!(matches!(items, RetainedItems::Some(3)));
        assert_eq!(up.size(), 3);
        assert_eq!(
            vec![ep(1), ep(3), ep(4)],
            up.iter().cloned().collect::<Vec<_>>()
        );

        let items = up.retain(|ep| ep.address.to_string().as_str() != "127.0.0.3:8080");
        assert!(matches!(items, RetainedItems::Some(2)));
        assert_eq!(up.size(), 2);
        assert_eq!(vec![ep(1), ep(4)], up.iter().cloned().collect::<Vec<_>>());

        // test an empty result on retain
        let result = up.retain(|_| false);
        assert!(result.is_none());

        let mut up: UpstreamEndpoints = Endpoints::new(initial_endpoints).unwrap().into();
        let result = up.retain(|_| false);
        assert!(result.is_none());
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
    #[test]
    fn yaml_parse_endpoint_metadata() {
        let yaml = "
 user:
     key1: value1
 quilkin.dev:
     tokens:
         - MXg3aWp5Ng== #1x7ijy6
         - OGdqM3YyaQ== #8gj3v2i
 ";
        assert_eq!(
            serde_json::to_value(serde_yaml::from_str::<Metadata<EndpointMetadata>>(yaml).unwrap())
                .unwrap(),
            serde_json::json!({
                "user": {
                    "key1": "value1"
                },
                "quilkin.dev": {
                    "tokens": ["MXg3aWp5Ng==", "OGdqM3YyaQ=="],
                }
            })
        );
    }

    #[test]
    fn yaml_parse_invalid_endpoint_metadata() {
        let not_a_list = "
 quilkin.dev:
     tokens: OGdqM3YyaQ==
 ";
        let not_a_string_value = "
 quilkin.dev:
     tokens:
         - map:
           a: b
 ";
        let not_a_base64_string = "
 quilkin.dev:
     tokens:
         - OGdqM3YyaQ== #8gj3v2i
         - iix
 ";
        for yaml in &[not_a_list, not_a_string_value, not_a_base64_string] {
            serde_yaml::from_str::<Metadata<EndpointMetadata>>(yaml).unwrap_err();
        }
    }
}
