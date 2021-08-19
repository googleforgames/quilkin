/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::fmt;

#[derive(thiserror::Error, Debug)]
pub enum TestSuiteDecodeError {
    #[error(
        "Expected Quilkin configuration. Configuration must be either \
             included in the test suite, or set `config` in your test suite."
    )]
    MissingConfig,
    #[error(
        "Expected Quilkin a test suite after the configuration. Ensure \
             there is a `---` separating the documents."
    )]
    MissingTestOptions,
    #[error(
        "Expected `config` key in the test suite, because no configuration \
             was found included."
    )]
    MissingConfigInTestOptions,
    #[error("Decoding error: {0}")]
    Yaml(serde_yaml::Error),
    #[error("i/o error: {0}")]
    Io(std::io::Error),
}

impl From<serde_yaml::Error> for TestSuiteDecodeError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::Yaml(value)
    }
}

impl From<std::io::Error> for TestSuiteDecodeError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, PartialEq)]
pub struct ValueInvalidArgs {
    pub field: String,
    pub clarification: Option<String>,
    pub examples: Option<Vec<String>>,
}

/// Validation failure for a Config
#[derive(Debug, PartialEq)]
pub enum ValidationError {
    NotUnique(String),
    EmptyList(String),
    ValueInvalid(ValueInvalidArgs),
    FilterInvalid(crate::filters::Error),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::NotUnique(field) => write!(f, "field {} is not unique", field),
            ValidationError::EmptyList(field) => write!(f, "field {} is cannot be an empty", field),
            ValidationError::ValueInvalid(args) => write!(
                f,
                "{} has an invalid value{}{}",
                args.field,
                args.clarification
                    .as_ref()
                    .map(|v| format!(": {}", v))
                    .unwrap_or_default(),
                args.examples
                    .as_ref()
                    .map(|v| format!("examples: {}", v.join(",")))
                    .unwrap_or_default()
            ),
            ValidationError::FilterInvalid(reason) => {
                write!(f, "filter configuration is invalid: {}", reason)
            }
        }
    }
}
