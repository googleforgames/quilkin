/*
 * Copyright 2021 Google LLC
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

use std::convert::TryFrom;

use crate::xds::envoy::config::core::v3::Metadata as ProtoMetadata;

pub const KEY: &str = "quilkin.dev";

/// Represents metadata attached to specific object.
#[derive(
    Default, Debug, serde::Deserialize, serde::Serialize, PartialEq, Clone, PartialOrd, Eq,
)]
#[non_exhaustive]
pub struct Metadata<T> {
    /// Known Quilkin metadata.
    #[serde(default, rename = "quilkin.dev")]
    pub known: T,
    /// User created metadata.
    #[serde(flatten)]
    pub unknown: serde_yaml::Mapping,
}

// This impl means that any `T` that we can try convert from a protobuf struct
// at run-time can be constructed statically without going through
// conversion first.
impl<T, E> From<T> for Metadata<T>
where
    T: TryFrom<prost_types::Struct, Error = E> + Default,
{
    fn from(known: T) -> Self {
        Self {
            known,
            unknown: <_>::default(),
        }
    }
}

impl<T, E> TryFrom<ProtoMetadata> for Metadata<T>
where
    T: TryFrom<prost_types::Struct, Error = E> + Default,
{
    type Error = E;

    fn try_from(mut value: ProtoMetadata) -> Result<Self, Self::Error> {
        let known = value
            .filter_metadata
            .remove(KEY)
            .map(T::try_from)
            .transpose()?
            .unwrap_or_default();

        let value = prost_types::value::Kind::StructValue(prost_types::Struct {
            fields: value
                .filter_metadata
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        prost_types::Value {
                            kind: Some(prost_types::value::Kind::StructValue(v)),
                        },
                    )
                })
                .collect(),
        });

        Ok(Self {
            known,
            unknown: crate::prost::mapping_from_kind(value).unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_metadata() {
        let metadata = crate::endpoint::Metadata {
            tokens: vec!["Man".into()].into_iter().collect(),
        };

        assert_eq!(
            serde_json::to_value(Metadata::from(metadata)).unwrap(),
            serde_json::json!({
                KEY: {
                    "tokens": ["TWFu"],
                }
            })
        );
    }
}
