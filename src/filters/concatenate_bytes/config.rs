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

use base64_serde::base64_serde_type;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{filters::prelude::*, map_proto_enum};

use super::proto;

base64_serde_type!(Base64Standard, base64::STANDARD);

#[derive(Serialize, Deserialize, Debug, PartialEq, JsonSchema)]
pub enum Strategy {
    #[serde(rename = "APPEND")]
    Append,
    #[serde(rename = "PREPEND")]
    Prepend,
    #[serde(rename = "DO_NOTHING")]
    DoNothing,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::DoNothing
    }
}

impl From<Strategy> for proto::concatenate_bytes::Strategy {
    fn from(strategy: Strategy) -> Self {
        match strategy {
            Strategy::Append => Self::Append,
            Strategy::Prepend => Self::Prepend,
            Strategy::DoNothing => Self::DoNothing,
        }
    }
}

impl From<Strategy> for proto::concatenate_bytes::StrategyValue {
    fn from(strategy: Strategy) -> Self {
        Self {
            value: proto::concatenate_bytes::Strategy::from(strategy) as i32,
        }
    }
}

/// Config represents a `ConcatenateBytes` filter configuration.
#[derive(Serialize, Deserialize, Debug, PartialEq, JsonSchema)]
#[non_exhaustive]
pub struct Config {
    /// Whether or not to `append` or `prepend` or `do nothing` on Filter `Read`
    #[serde(default)]
    pub on_read: Strategy,
    /// Whether or not to `append` or `prepend` or `do nothing` on Filter `Write`
    #[serde(default)]
    pub on_write: Strategy,

    #[serde(
        deserialize_with = "Base64Standard::deserialize",
        serialize_with = "Base64Standard::serialize"
    )]
    pub bytes: Vec<u8>,
}

impl From<Config> for proto::ConcatenateBytes {
    fn from(config: Config) -> Self {
        Self {
            on_read: Some(config.on_read.into()),
            on_write: Some(config.on_write.into()),
            bytes: config.bytes,
        }
    }
}

impl TryFrom<proto::ConcatenateBytes> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: proto::ConcatenateBytes) -> Result<Self, Self::Error> {
        let on_read = p
            .on_read
            .map(|strategy| {
                map_proto_enum!(
                    value = strategy.value,
                    field = "on_read",
                    proto_enum_type = proto::concatenate_bytes::Strategy,
                    target_enum_type = Strategy,
                    variants = [DoNothing, Append, Prepend]
                )
            })
            .transpose()?
            .unwrap_or_default();

        let on_write = p
            .on_write
            .map(|strategy| {
                map_proto_enum!(
                    value = strategy.value,
                    field = "on_write",
                    proto_enum_type = proto::concatenate_bytes::Strategy,
                    target_enum_type = Strategy,
                    variants = [DoNothing, Append, Prepend]
                )
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            on_read,
            on_write,
            bytes: p.bytes,
        })
    }
}
