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

mod address;
mod locality;

use serde::{Deserialize, Serialize};

use crate::xds::config::endpoint::v3::{lb_endpoint::HostIdentifier, Endpoint as EnvoyEndpoint};

pub use self::{
    address::{EndpointAddress, ToSocketAddrError},
    locality::{Locality, LocalityEndpoints},
};

type EndpointMetadata = crate::metadata::MetadataView<Metadata>;

/// A destination endpoint with any associated metadata.
#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Eq, schemars::JsonSchema)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    #[schemars(with = "String")]
    pub address: EndpointAddress,
    #[serde(default)]
    pub metadata: EndpointMetadata,
}

impl Endpoint {
    /// Creates a new [`Endpoint`] with no metadata.
    pub fn new(address: EndpointAddress) -> Self {
        Self {
            address,
            ..<_>::default()
        }
    }

    /// Creates a new [`Endpoint`] with the specified `metadata`.
    pub fn with_metadata(address: EndpointAddress, metadata: impl Into<EndpointMetadata>) -> Self {
        Self {
            address,
            metadata: metadata.into(),
            ..<_>::default()
        }
    }
}

impl Default for Endpoint {
    fn default() -> Self {
        Self {
            address: EndpointAddress::UNSPECIFIED,
            metadata: <_>::default(),
        }
    }
}

impl std::str::FromStr for Endpoint {
    type Err = <EndpointAddress as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            address: s.parse()?,
            ..Self::default()
        })
    }
}

impl From<Endpoint> for crate::xds::config::endpoint::v3::LbEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        Self {
            host_identifier: Some(HostIdentifier::Endpoint(EnvoyEndpoint {
                address: Some(endpoint.address.into()),
                ..<_>::default()
            })),
            metadata: Some(endpoint.metadata.into()),
            ..<_>::default()
        }
    }
}

impl TryFrom<crate::xds::config::endpoint::v3::LbEndpoint> for Endpoint {
    type Error = eyre::Error;

    fn try_from(
        endpoint: crate::xds::config::endpoint::v3::LbEndpoint,
    ) -> Result<Self, Self::Error> {
        let address = match endpoint.host_identifier {
            Some(HostIdentifier::Endpoint(endpoint)) => EndpointAddress::try_from(endpoint)?,
            _ => return Err(eyre::eyre!("Endpoint host identifier not supported")),
        };

        Ok(Self {
            address,
            metadata: endpoint
                .metadata
                .map(crate::metadata::MetadataView::try_from)
                .transpose()?
                .unwrap_or_default(),
            ..<_>::default()
        })
    }
}

impl std::cmp::PartialEq<EndpointAddress> for Endpoint {
    fn eq(&self, rhs: &EndpointAddress) -> bool {
        self.address == *rhs
    }
}

impl<T: Into<EndpointAddress>> From<T> for Endpoint {
    fn from(value: T) -> Self {
        Self::new(value.into())
    }
}

impl Ord for Endpoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl PartialOrd for Endpoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.address.partial_cmp(&other.address)
    }
}

/// Metadata specific to endpoints.
#[derive(
    Default, Debug, Deserialize, Serialize, PartialEq, Clone, PartialOrd, Eq, schemars::JsonSchema,
)]
#[non_exhaustive]
pub struct Metadata {
    #[serde(
        serialize_with = "base64_set::serialize",
        deserialize_with = "base64_set::deserialize"
    )]
    pub tokens: base64_set::Set,
}

impl From<Metadata> for prost_types::Struct {
    fn from(metadata: Metadata) -> Self {
        let tokens = prost_types::Value {
            kind: Some(prost_types::value::Kind::ListValue(
                prost_types::ListValue {
                    values: metadata
                        .tokens
                        .into_iter()
                        .map(base64::encode)
                        .map(prost_types::value::Kind::StringValue)
                        .map(|k| prost_types::Value { kind: Some(k) })
                        .collect(),
                },
            )),
        };

        Self {
            fields: <_>::from([("tokens".into(), tokens)]),
        }
    }
}

impl std::convert::TryFrom<prost_types::Struct> for Metadata {
    type Error = MetadataError;

    fn try_from(mut value: prost_types::Struct) -> Result<Self, Self::Error> {
        use prost_types::value::Kind;
        const TOKENS: &str = "tokens";

        let tokens = if let Some(kind) = value.fields.remove(TOKENS).and_then(|v| v.kind) {
            match kind {
                Kind::ListValue(list) => list
                    .values
                    .into_iter()
                    .filter_map(|v| v.kind)
                    .map(|kind| {
                        if let Kind::StringValue(string) = kind {
                            base64::decode(string).map_err(MetadataError::InvalidBase64)
                        } else {
                            Err(MetadataError::InvalidType {
                                key: "quilkin.dev.tokens",
                                expected: "base64 string",
                            })
                        }
                    })
                    .collect::<Result<_, _>>()?,
                Kind::StringValue(string) => {
                    <_>::from([base64::decode(string).map_err(MetadataError::InvalidBase64)?])
                }
                _ => return Err(MetadataError::MissingKey(TOKENS)),
            }
        } else {
            <_>::default()
        };

        Ok(Self { tokens })
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

/// A module for providing base64 encoding for a `BTreeSet` at the `serde`
/// boundary. Accepts a list of strings representing Base64 encoded data,
/// this list is then converted into its binary representation while in memory,
/// and then encoded back as a list of base64 strings.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_metadata() {
        let metadata = Metadata {
            tokens: vec!["Man".into()].into_iter().collect(),
        };

        assert_eq!(
            serde_json::to_value(EndpointMetadata::from(metadata)).unwrap(),
            serde_json::json!({
                crate::metadata::KEY: {
                    "tokens": ["TWFu"],
                }
            })
        );
    }

    #[test]
    fn parse_dns_endpoints() {
        let localhost = "address: localhost:80";
        serde_yaml::from_str::<Endpoint>(localhost).unwrap();
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
            serde_yaml::from_str::<EndpointMetadata>(yaml).unwrap_err();
        }
    }
}
