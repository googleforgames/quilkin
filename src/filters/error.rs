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

#[derive(thiserror::Error)]
#[error("{}{} error: {source}", .label.as_deref().map(|label| format!("{}:", label)).unwrap_or_default(), .name.as_deref().unwrap_or_default())]
pub struct FilterError {
    name: Option<String>,
    label: Option<String>,
    source: Box<dyn std::error::Error + Send + Sync + 'static>,
}

impl FilterError {
    pub fn new<D: std::fmt::Display>(error: D) -> Self {
        Self {
            name: None,
            label: None,
            source: Box::from(error.to_string()),
        }
    }
}

impl From<std::io::Error> for FilterError {
    fn from(error: std::io::Error) -> Self {
        Self::new(error)
    }
}

impl std::fmt::Debug for FilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilterError")
            .field("name", &self.name)
            .field("label", &self.label)
            .field("source", &self.source.to_string())
            .finish()
    }
}

/// An error that occurred when attempting to create a [`Filter`] from
/// a [`FilterFactory`].
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum CreationError {
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

impl From<std::convert::Infallible> for CreationError {
    fn from(_: std::convert::Infallible) -> Self {
        Self::Infallible
    }
}

impl From<MetricsError> for CreationError {
    fn from(error: MetricsError) -> Self {
        Self::InitializeMetricsFailed(error.to_string())
    }
}

impl From<serde_yaml::Error> for CreationError {
    fn from(error: serde_yaml::Error) -> Self {
        Self::DeserializeFailed(error.to_string())
    }
}

impl From<serde_json::Error> for CreationError {
    fn from(error: serde_json::Error) -> Self {
        Self::DeserializeFailed(error.to_string())
    }
}

impl From<prost::EncodeError> for CreationError {
    fn from(error: prost::EncodeError) -> Self {
        Self::ConvertProtoConfig(ConvertProtoConfigError::new(error, None))
    }
}

impl From<prost::DecodeError> for CreationError {
    fn from(error: prost::DecodeError) -> Self {
        Self::ConvertProtoConfig(ConvertProtoConfigError::new(error, None))
    }
}

impl From<ConvertProtoConfigError> for CreationError {
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
