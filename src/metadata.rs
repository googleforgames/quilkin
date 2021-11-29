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

use std::{collections::HashMap, convert::TryFrom, sync::Arc};

use crate::xds::envoy::config::core::v3::Metadata as ProtoMetadata;

/// Shared state between [`Filter`][crate::filters::Filter]s during processing for a single packet.
pub type DynamicMetadata = HashMap<Arc<String>, Value>;

pub const KEY: &str = "quilkin.dev";

#[derive(Clone, Debug, PartialOrd, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum Value {
    Bool(bool),
    Number(u64),
    List(Vec<Value>),
    String(String),
    Bytes(bytes::Bytes),
}

impl Value {
    /// Returns the inner `String` value of `self` if it
    /// matches [`Value::String`].
    pub fn as_bytes(&self) -> Option<&bytes::Bytes> {
        match self {
            Self::Bytes(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the inner `String` value of `self` if it
    /// matches [`Value::String`].
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the inner `String` value of `self` if it
    /// matches [`Value::String`].
    pub fn as_mut_string(&mut self) -> Option<&mut String> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

macro_rules! from_value {
    (($name:ident) { $($typ:ty => $ex:expr),+ $(,)? }) => {
        $(
            impl From<$typ> for Value {
                fn from($name: $typ) -> Self {
                    $ex
                }
            }
        )+
    }
}

from_value! {
    (value) {
        bool => Self::Bool(value),
        u64 => Self::Number(value),
        Vec<Self> => Self::List(value),
        String => Self::String(value),
        &str => Self::String(value.into()),
        bytes::Bytes => Self::Bytes(value),
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Number(a), Self::Number(b)) => a == b,
            (Self::List(a), Self::List(b)) => a == b,
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Bytes(a), Self::Bytes(b)) => a == b,
            (Self::String(a), Self::Bytes(b)) | (Self::Bytes(b), Self::String(a)) => a == b,
            _ => false,
        }
    }
}

/// Represents a view into the metadata object attached to another object. `T`
/// represents metadata known to Quilkin under `quilkin.dev` (available under
/// the [`KEY`] constant.)
#[derive(
    Default, Debug, serde::Deserialize, serde::Serialize, PartialEq, Clone, PartialOrd, Eq,
)]
#[non_exhaustive]
pub struct MetadataView<T> {
    /// Known Quilkin metadata.
    #[serde(default, rename = "quilkin.dev")]
    pub known: T,
    /// User created metadata.
    #[serde(flatten)]
    pub unknown: serde_yaml::Mapping,
}

impl<T> MetadataView<T> {
    pub fn with_unknown(known: impl Into<T>, unknown: serde_yaml::Mapping) -> Self {
        Self {
            known: known.into(),
            unknown,
        }
    }
}

// This impl means that any `T` that we can try convert from a protobuf struct
// at run-time can be constructed statically without going through
// conversion first.
impl<T, E> From<T> for MetadataView<T>
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

impl<T, E> TryFrom<ProtoMetadata> for MetadataView<T>
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
