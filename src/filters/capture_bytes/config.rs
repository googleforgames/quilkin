/*
 * Copyright 2021 Google LLC All Rights Reserved.
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

use super::proto::quilkin::extensions::filters::capture_bytes::v1alpha1::{
    capture_bytes::Strategy as ProtoStrategy, CaptureBytes as ProtoConfig,
};
use crate::filters::{metadata::CAPTURED_BYTES, ConvertProtoConfigError};
use crate::map_proto_enum;

use super::capture::{Capture, Prefix, Regex, Suffix};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Config {
    /// the key to use when storing the captured bytes in the filter context
    #[serde(rename = "metadataKey")]
    #[serde(default = "default_metadata_key")]
    pub metadata_key: String,

    #[serde(flatten)]
    pub strategy: Strategy,
}

/// default value for the context key in the Config
fn default_metadata_key() -> String {
    CAPTURED_BYTES.into()
}

/// default value for [`Config::strategy::remove`].
fn default_remove() -> bool {
    false
}

/// default value for [`Config::strategy::expression`].
fn default_expression() -> String {
    ".*".to_string()
}

/// default value for [`Config::strategy::passthrough`].
fn default_passthrough() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum Strategy {
    #[serde(rename = "prefix")]
    Prefix {
        /// the number of bytes to capture
        #[serde(rename = "size")]
        size: usize,
        /// whether or not to remove the set of the bytes from the packet once captured
        #[serde(default = "default_remove")]
        remove: bool,
    },
    #[serde(rename = "suffix")]
    Suffix {
        // /// the number of bytes to capture
        #[serde(rename = "size")]
        size: usize,
        /// whether or not to remove the set of the bytes from the packet once captured
        #[serde(default = "default_remove")]
        remove: bool,
    },
    #[serde(rename = "regex")]
    Regex {
        #[serde(default = "default_expression")]
        expression: String,
        /// whether or not to remove the set of the bytes from the packet once captured
        #[serde(default = "default_remove")]
        remove: bool,
        #[serde(default = "default_passthrough")]
        passthrough: bool,
    },
}

impl Strategy {
    pub(crate) fn as_capture(&self) -> Box<dyn Capture + Send + Sync> {
        match self {
            Self::Prefix { size, remove } => Box::new(Prefix {}),
            Self::Suffix { size, remove } => Box::new(Suffix {}),
            Self::Regex {
                expression,
                remove,
                passthrough,
            } => Box::new(Regex {}),
        }
    }
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::Suffix {
            size: 0,
            remove: false,
        }
    }
}

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> Result<Self, Self::Error> {
        let strategy = p
            .strategy
            .map(|strategy| {
                map_proto_enum!(
                    value = strategy.value,
                    field = "strategy",
                    proto_enum_type = ProtoStrategy,
                    target_enum_type = Strategy,
                    variants = [Suffix, Prefix, Regex]
                )
            })
            .transpose()?
            .unwrap_or_else(Strategy::default);

        Ok(Self {
            strategy,
            metadata_key: p.metadata_key.unwrap_or_else(default_metadata_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::super::proto::quilkin::extensions::filters::capture_bytes::v1alpha1::{
        capture_bytes::{Strategy as ProtoStrategy, StrategyValue},
        CaptureBytes as ProtoConfig,
    };
    use super::*;

    #[test]
    fn convert_proto_config() {
        let test_cases = vec![
            (
                "should succeed when all valid values are provided",
                ProtoConfig {
                    strategy: Some(StrategyValue {
                        value: ProtoStrategy::Suffix as i32,
                    }),
                    size: 42,
                    metadata_key: Some("foobar".into()),
                    remove: Some(true),
                    expression: None,
                    passthrough: None,
                },
                Some(Config {
                    strategy: Strategy::Suffix {
                        size: 43,
                        remove: true,
                    },
                    metadata_key: "foobar".into(),
                }),
            ),
            (
                "should fail when invalid strategy is provided",
                ProtoConfig {
                    strategy: Some(StrategyValue { value: 42 }),
                    size: 42,
                    metadata_key: Some("foobar".into()),
                    remove: Some(true),
                    expression: None,
                    passthrough: None,
                },
                None,
            ),
            (
                "should use correct default values",
                ProtoConfig {
                    strategy: None,
                    size: 42,
                    metadata_key: None,
                    remove: None,
                    expression: None,
                    passthrough: None,
                },
                Some(Config {
                    strategy: Strategy::default(),
                    metadata_key: default_metadata_key(),
                }),
            ),
        ];
        for (name, proto_config, expected) in test_cases {
            let result = Config::try_from(proto_config);
            assert_eq!(
                result.is_err(),
                expected.is_none(),
                "{}: error expectation does not match",
                name
            );
            if let Some(expected) = expected {
                assert_eq!(expected, result.unwrap(), "{}", name);
            }
        }
    }
}
