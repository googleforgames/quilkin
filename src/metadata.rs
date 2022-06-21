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

use crate::xds::config::core::v3::Metadata as ProtoMetadata;

#[doc(hidden)]
pub mod build {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

/// Shared state between [`Filter`][crate::filters::Filter]s during processing for a single packet.
pub type DynamicMetadata = HashMap<Arc<String>, Value>;

pub const KEY: &str = "quilkin.dev";

#[derive(
    Clone, Debug, PartialOrd, serde::Serialize, serde::Deserialize, Eq, Ord, schemars::JsonSchema,
)]
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

/// Convenience macro for generating From<T> implementations.
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

impl<const N: usize> From<[u8; N]> for Value {
    fn from(value: [u8; N]) -> Self {
        Self::Bytes(bytes::Bytes::copy_from_slice(&value))
    }
}

impl<const N: usize> From<&[u8; N]> for Value {
    fn from(value: &[u8; N]) -> Self {
        Self::Bytes(bytes::Bytes::copy_from_slice(value))
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Bool(_), _) => false,
            (Self::Number(a), Self::Number(b)) => a == b,
            (Self::Number(num), Self::Bytes(bytes)) => {
                bytes.len() == 1 && *num == u64::from(bytes[0])
            }
            (Self::Number(_), _) => false,
            (Self::List(a), Self::List(b)) => a == b,
            (Self::List(_), _) => false,
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Bytes(a), Self::Bytes(b)) => a == b,
            (Self::String(a), Self::Bytes(b)) | (Self::Bytes(b), Self::String(a)) => a == b,
            (Self::String(_), _) => false,
            (Self::Bytes(_), _) => false,
        }
    }
}

impl From<Value> for prost_types::Value {
    fn from(value: Value) -> Self {
        use prost_types::value::Kind;

        Self {
            kind: Some(match value {
                Value::Number(number) => Kind::NumberValue(number as f64),
                Value::String(string) => Kind::StringValue(string),
                Value::Bool(value) => Kind::BoolValue(value),
                Value::Bytes(bytes) => Kind::ListValue(prost_types::ListValue {
                    values: bytes
                        .into_iter()
                        .map(|number| prost_types::Value {
                            kind: Some(Kind::NumberValue(number as f64)),
                        })
                        .collect(),
                }),
                Value::List(list) => Kind::ListValue(prost_types::ListValue {
                    values: list.into_iter().map(From::from).collect(),
                }),
            }),
        }
    }
}

impl TryFrom<prost_types::Value> for Value {
    type Error = eyre::Report;

    fn try_from(value: prost_types::Value) -> Result<Self, Self::Error> {
        use prost_types::value::Kind;

        let value = match value.kind {
            Some(value) => value,
            None => return Err(eyre::eyre!("unexpected missing value")),
        };

        match value {
            Kind::NullValue(_) => Err(eyre::eyre!("unexpected missing value")),
            Kind::NumberValue(number) => Ok(Self::Number(number as u64)),
            Kind::StringValue(string) => Ok(Self::String(string)),
            Kind::BoolValue(value) => Ok(Self::Bool(value)),
            Kind::ListValue(list) => Ok(Self::List(
                list.values
                    .into_iter()
                    .map(prost_types::Value::try_into)
                    .collect::<crate::Result<_>>()?,
            )),
            Kind::StructValue(_) => Err(eyre::eyre!("unexpected struct value")),
        }
    }
}

/// Represents a view into the metadata object attached to another object. `T`
/// represents metadata known to Quilkin under `quilkin.dev` (available under
/// the [`KEY`] constant.)
#[derive(
    Default, Debug, serde::Deserialize, serde::Serialize, PartialEq, Clone, Eq, schemars::JsonSchema,
)]
#[non_exhaustive]
pub struct MetadataView<T: Default> {
    /// Known Quilkin metadata.
    #[serde(default, rename = "quilkin.dev")]
    pub known: T,
    /// User created metadata.
    #[serde(flatten)]
    pub unknown: serde_json::Map<String, serde_json::Value>,
}

impl<T: Default> MetadataView<T> {
    pub fn new(known: impl Into<T>) -> Self {
        Self {
            known: known.into(),
            unknown: <_>::default(),
        }
    }

    pub fn with_unknown(
        known: impl Into<T>,
        unknown: serde_json::Map<String, serde_json::Value>,
    ) -> Self {
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

impl<T: Into<prost_types::Struct> + Default> From<MetadataView<T>> for ProtoMetadata {
    fn from(metadata: MetadataView<T>) -> Self {
        let mut filter_metadata = HashMap::new();
        filter_metadata.insert(String::from("quilkin.dev"), metadata.known.into());
        filter_metadata.extend(
            metadata
                .unknown
                .into_iter()
                .filter_map(|(k, v)| crate::prost::struct_from_json(v).map(|v| (k, v))),
        );

        Self {
            filter_metadata,
            ..<_>::default()
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
