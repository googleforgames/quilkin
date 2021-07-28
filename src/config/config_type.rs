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

use bytes::Bytes;

use crate::filters::{ConvertProtoConfigError, Error};

/// The configuration of a [`Filter`][crate::filters::Filter] from either a
/// static or dynamic source.
pub enum ConfigType<'a> {
    /// Static configuration from YAML.
    Static(&'a serde_yaml::Value),
    /// Dynamic configuration from Protobuf.
    Dynamic(prost_types::Any),
}

impl ConfigType<'_> {
    /// Deserializes the configuration to `T` based on the input type. Errors if
    /// the data produces an invalid config.
    pub fn deserialize<T, P>(self, filter_name: &str) -> Result<T, Error>
    where
        P: prost::Message + Default,
        T: for<'de> serde::Deserialize<'de> + TryFrom<P, Error = ConvertProtoConfigError>,
    {
        match self {
            ConfigType::Static(config) => serde_yaml::to_string(config)
                .and_then(|raw_config| serde_yaml::from_str(raw_config.as_str()))
                .map_err(|err| Error::DeserializeFailed(err.to_string())),
            ConfigType::Dynamic(config) => prost::Message::decode(Bytes::from(config.value))
                .map_err(|err| {
                    Error::DeserializeFailed(format!(
                        "filter `{}`: config decode error: {}",
                        filter_name,
                        err.to_string()
                    ))
                })
                .and_then(|config| T::try_from(config).map_err(Error::ConvertProtoConfig)),
        }
    }
}
