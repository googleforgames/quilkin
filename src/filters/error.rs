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

use prometheus::Error as MetricsError;

#[cfg(doc)]
use crate::filters::{Filter, FilterFactory};

/// An error that occurred when attempting to create a [`Filter`] from
/// a [`FilterFactory`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("filter `{}` not found", .0)]
    NotFound(String),
    #[error("Expected <{}> message, received <{}> ", expected, actual)]
    MismatchedTypes { expected: String, actual: String },
    #[error("filter `{}` requires configuration, but none provided", .0)]
    MissingConfig(&'static str),
    #[error("field `{}` is invalid, reason: {}", field, reason)]
    FieldInvalid { field: String, reason: String },
    #[error("Deserialization failed: {}", .0)]
    DeserializeFailed(String),
    #[error("Failed to initialize metrics: {}", .0)]
    InitializeMetricsFailed(String),
    #[error("Protobuf error: {}", .0)]
    ConvertProtoConfig(ConvertProtoConfigError),
    #[error("Infallible! This should never occur")]
    Infallible,
}

impl From<std::convert::Infallible> for Error {
    fn from(_: std::convert::Infallible) -> Self {
        Self::Infallible
    }
}

impl From<MetricsError> for Error {
    fn from(error: MetricsError) -> Self {
        Error::InitializeMetricsFailed(error.to_string())
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(error: serde_yaml::Error) -> Self {
        Self::DeserializeFailed(error.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::DeserializeFailed(error.to_string())
    }
}

impl From<prost::EncodeError> for Error {
    fn from(error: prost::EncodeError) -> Self {
        Self::ConvertProtoConfig(ConvertProtoConfigError::new(error, None))
    }
}

impl From<prost::DecodeError> for Error {
    fn from(error: prost::DecodeError) -> Self {
        Self::ConvertProtoConfig(ConvertProtoConfigError::new(error, None))
    }
}

impl From<ConvertProtoConfigError> for Error {
    fn from(error: ConvertProtoConfigError) -> Self {
        Self::ConvertProtoConfig(error)
    }
}

/// An error representing failure to convert a filter's protobuf configuration
/// to its static representation.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "{}failed to convert protobuf config: {}",
    self.field.as_ref().map(|f| format!("Field `{f}`")).unwrap_or_default(),
    reason
)]
pub struct ConvertProtoConfigError {
    /// Reason for the failure.
    reason: String,
    /// Set if the failure is specific to a single field in the config.
    field: Option<String>,
}

impl ConvertProtoConfigError {
    pub fn new(reason: impl std::fmt::Display, field: Option<String>) -> Self {
        Self {
            reason: reason.to_string(),
            field,
        }
    }

    pub fn missing_field(field: &'static str) -> Self {
        Self {
            reason: format!("`{field}` is required but not found"),
            field: Some(field.into()),
        }
    }
}
