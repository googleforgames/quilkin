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

use base64_serde::base64_serde_type;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::proto;

base64_serde_type!(Base64Standard, base64::STANDARD);

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, JsonSchema)]
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

impl From<proto::concatenate_bytes::Strategy> for Strategy {
    fn from(strategy: proto::concatenate_bytes::Strategy) -> Self {
        match strategy {
            proto::concatenate_bytes::Strategy::Append => Self::Append,
            proto::concatenate_bytes::Strategy::Prepend => Self::Prepend,
            proto::concatenate_bytes::Strategy::DoNothing => Self::DoNothing,
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
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, JsonSchema)]
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

impl From<proto::ConcatenateBytes> for Config {
    fn from(p: proto::ConcatenateBytes) -> Self {
        let on_read = p
            .on_read
            .map(|p| p.value())
            .map(Strategy::from)
            .unwrap_or_default();

        let on_write = p
            .on_write
            .map(|p| p.value())
            .map(Strategy::from)
            .unwrap_or_default();

        Self {
            on_read,
            on_write,
            bytes: p.bytes,
        }
    }
}
