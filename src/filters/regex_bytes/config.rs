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

use super::proto::quilkin::extensions::filters::regex_bytes::v1alpha1::RegexBytes as ProtoConfig;
use crate::filters::{metadata::REGEX, ConvertProtoConfigError};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Config {
    /// the regex expression
    #[serde(rename = "regex")]
    pub regex_expression: String,
    /// the key to use when storing the captured bytes in the filter context
    #[serde(rename = "metadataKey")]
    #[serde(default = "default_metadata_key")]
    pub metadata_key: String,
}

/// default value for the context key in the Config
fn default_metadata_key() -> String {
    REGEX.into()
}

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            regex_expression: p.regex_expression.unwrap_or_default(),
            metadata_key: p.metadata_key.unwrap_or_else(default_metadata_key),
        })
    }
}
