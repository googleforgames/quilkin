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

use std::fmt;

use crate::config::ValidationError;
use prometheus::Error as MetricsError;

#[cfg(doc)]
use crate::filters::{Filter, FilterFactory};

/// An error that occurred when attempting to create a [`Filter`] from
/// a [`FilterFactory`].
#[derive(Debug, PartialEq)]
pub enum Error {
    NotFound(String),
    MissingConfig(&'static str),
    FieldInvalid { field: String, reason: String },
    DeserializeFailed(String),
    InitializeMetricsFailed(String),
    ConvertProtoConfig(ConvertProtoConfigError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound(key) => write!(f, "filter {} is not found", key),
            Error::MissingConfig(filter_name) => {
                write!(f, "filter `{}` requires a configuration", filter_name)
            }
            Error::FieldInvalid { field, reason } => {
                write!(f, "field {} is invalid: {}", field, reason)
            }
            Error::DeserializeFailed(reason) => write!(f, "Deserialization failed: {}", reason),
            Error::InitializeMetricsFailed(reason) => {
                write!(f, "failed to initialize metrics: {}", reason)
            }
            Error::ConvertProtoConfig(inner) => write!(f, "{}", inner),
        }
    }
}

impl From<Error> for ValidationError {
    fn from(error: Error) -> Self {
        Self::FilterInvalid(error)
    }
}

impl From<MetricsError> for Error {
    fn from(error: MetricsError) -> Self {
        Error::InitializeMetricsFailed(error.to_string())
    }
}

/// An error representing failure to convert a filter's protobuf configuration
/// to its static representation.
#[derive(Debug, PartialEq)]
pub struct ConvertProtoConfigError {
    /// Reason for the failure.
    reason: String,
    /// Set if the failure is specific to a single field in the config.
    field: Option<String>,
}

impl fmt::Display for ConvertProtoConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}failed to convert protobuf config: {}",
            self.field
                .as_ref()
                .map(|f| format!("field `{}`: ", f))
                .unwrap_or_default(),
            self.reason
        )
    }
}

impl ConvertProtoConfigError {
    pub fn new(reason: impl Into<String>, field: Option<String>) -> Self {
        Self {
            reason: reason.into(),
            field,
        }
    }
}

/// Returns a [`ConvertProtoConfigError`] with an error message when
/// an invalid proto enum value was provided in a filter's proto config.
#[macro_export]
macro_rules! enum_no_match_error {
    (
        field = $field:literal,
        invalid_value = $invalid_value:ident,
        enum_type = $enum_type:ty,
        allowed_values = [ $( $allowed_value:tt ),+ ]
    ) => {
        Err($crate::filters::error::ConvertProtoConfigError::new(
            format!(
              "invalid value `{}` provided: allowed values are {}",
              $invalid_value,
              vec![
                $( (stringify!($allowed_value), <$enum_type>::$allowed_value as i32) ),+
              ]
              .into_iter()
              .map(|(a, b)| format!("{} => {}", a, b as i32))
              .collect::<Vec<_>>()
              .join(", ")
            ),
            Some($field.into()),
        ))
    };
}

/// Maps an integer from a protobuf enum value to a target enum variant.
/// Both protobuf and target enum must have similar variants.
/// The protobuf enum variant should be cast-able to an i32
/// Returns an `OK` Result with the target enum variant otherwise [`ConvertProtoConfigError`]
/// if the provided value does not map to any enum variant.
#[macro_export]
macro_rules! map_proto_enum {
    (
        value = $value:expr,
        field = $field:literal,
        proto_enum_type = $proto_enum_type:ty,
        target_enum_type = $target_enum_type:ty,
        variants = [ $( $variant:tt ),+ ]
    ) => {
        match $value {
            $( v if v == <$proto_enum_type>::$variant as i32 => Ok(<$target_enum_type>::$variant) ),+,
            invalid => $crate::enum_no_match_error!(
                field = $field,
                invalid_value = invalid,
                enum_type = $proto_enum_type,
                allowed_values = [ $( $variant ),+ ]
            )
        }
    }
}
