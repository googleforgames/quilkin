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
    /// Deserializes takes two type arguments `Static` and `Dynamic` representing
    /// the types of a static and dynamic configuration respectively.
    ///
    /// If the configuration input is a [ConfigType::Static], then it is directly
    /// marshalled into the returned `Static` instance.
    ///
    /// Otherwise if the input is a [ConfigType::Dynamic] then the contained Protobuf
    /// data is decoded into a type `Dynamic` instance, after which the decoded
    /// value is converted into the returned `Static` instance.
    /// As a result [TryFrom] must be implemented from the `Dynamic` to the `Static`
    /// type.
    ///
    /// It returns both the marshalled, as well as, a JSON representation
    /// of the provided config.
    /// It returns an error if any of the serialization or deserialization steps fail.
    pub fn deserialize<Static, Dynamic>(
        self,
        filter_name: &str,
    ) -> Result<(serde_json::Value, Static), Error>
    where
        Dynamic: prost::Message + Default,
        Static: serde::Serialize
            + for<'de> serde::Deserialize<'de>
            + TryFrom<Dynamic, Error = ConvertProtoConfigError>,
    {
        match self {
            ConfigType::Static(config) => serde_yaml::to_string(config)
                .and_then(|raw_config| serde_yaml::from_str(raw_config.as_str()))
                .map_err(|err| {
                    Error::DeserializeFailed(format!(
                        "filter `{}`: failed to YAML deserialize config: {}",
                        filter_name,
                        err.to_string()
                    ))
                })
                .and_then(|config| Self::get_json_config(filter_name, config)),
            ConfigType::Dynamic(config) => prost::Message::decode(Bytes::from(config.value))
                .map_err(|err| {
                    Error::DeserializeFailed(format!(
                        "filter `{}`: config decode error: {}",
                        filter_name,
                        err.to_string()
                    ))
                })
                .and_then(|config| Static::try_from(config).map_err(Error::ConvertProtoConfig))
                .and_then(|config| Self::get_json_config(filter_name, config)),
        }
    }

    // Returns an equivalent json value for the passed in config.
    fn get_json_config<T>(filter_name: &str, config: T) -> Result<(serde_json::Value, T), Error>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        serde_json::to_string(&config)
            .map_err(|err| {
                Error::DeserializeFailed(format!(
                    "filter `{}`: failed to serialize config to json: {}",
                    filter_name,
                    err.to_string()
                ))
            })
            .and_then(|config_json| {
                serde_json::from_str::<serde_json::Value>(config_json.as_str()).map_err(|err| {
                    Error::DeserializeFailed(format!(
                        "filter `{}`: failed to deserialize into json: {}",
                        filter_name,
                        err.to_string()
                    ))
                })
            })
            .map(|config_json| (config_json, config))
    }
}

#[cfg(test)]
mod tests {
    use super::ConfigType;
    use serde::{Deserialize, Serialize};

    #[test]
    fn get_json_config() {
        #[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
        struct TestConfig {
            name: String,
            value: usize,
        }
        let expected_config = TestConfig {
            name: "bebop".into(),
            value: 98,
        };
        let (config_json, config) =
            ConfigType::get_json_config("my-filter", expected_config.clone()).unwrap();

        assert_eq!(expected_config, config);
        assert_eq!(
            serde_json::json!({
                "name": "bebop",
                "value": 98,
            }),
            config_json
        )
    }
}
