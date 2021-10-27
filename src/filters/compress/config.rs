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

use serde::{Deserialize, Serialize};

use super::compressor::{Compressor, Snappy};
use super::quilkin::extensions::filters::compress::v1alpha1::{
    compress::Action as ProtoAction, compress::Mode as ProtoMode, Compress as ProtoConfig,
};
use crate::{filters::ConvertProtoConfigError, map_proto_enum};

/// The library to use when compressing.
#[derive(Clone, Copy, Deserialize, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub enum Mode {
    // we only support one mode for now, but adding in the config option to
    // provide the option to expand for later.
    #[serde(rename = "SNAPPY")]
    Snappy,
}

impl Mode {
    pub(crate) fn as_compressor(&self) -> Box<dyn Compressor + Send + Sync> {
        match self {
            Self::Snappy => Box::from(Snappy {}),
        }
    }
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Snappy
    }
}

/// Whether to do nothing, compress or decompress the packet.
#[derive(Clone, Copy, Deserialize, Debug, PartialEq, Serialize)]
pub enum Action {
    #[serde(rename = "DO_NOTHING")]
    DoNothing,
    #[serde(rename = "COMPRESS")]
    Compress,
    #[serde(rename = "DECOMPRESS")]
    Decompress,
}

impl Default for Action {
    fn default() -> Self {
        Action::DoNothing
    }
}

#[derive(Clone, Copy, Deserialize, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    pub on_read: Action,
    pub on_write: Action,
}

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> std::result::Result<Self, Self::Error> {
        let mode = p
            .mode
            .map(|mode| {
                map_proto_enum!(
                    value = mode.value,
                    field = "mode",
                    proto_enum_type = ProtoMode,
                    target_enum_type = Mode,
                    variants = [Snappy]
                )
            })
            .transpose()?
            .unwrap_or_default();

        let on_read = p
            .on_read
            .map(|on_read| {
                map_proto_enum!(
                    value = on_read.value,
                    field = "on_read",
                    proto_enum_type = ProtoAction,
                    target_enum_type = Action,
                    variants = [DoNothing, Compress, Decompress]
                )
            })
            .transpose()?
            .unwrap_or_default();

        let on_write = p
            .on_write
            .map(|on_write| {
                map_proto_enum!(
                    value = on_write.value,
                    field = "on_write",
                    proto_enum_type = ProtoAction,
                    target_enum_type = Action,
                    variants = [DoNothing, Compress, Decompress]
                )
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            mode,
            on_read,
            on_write,
        })
    }
}
