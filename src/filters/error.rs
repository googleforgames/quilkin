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

use crate::filters;
use std::{fmt, io::ErrorKind};

#[cfg(doc)]
use filters::{Filter, FilterFactory};

/// All possible errors that can be returned from [`Filter`] implementations
#[derive(Debug)]
pub enum FilterError {
    Capture(filters::capture::NoValueCaptured),
    TokenRouter(filters::token_router::Error),
    Compression(filters::compress::Error),
    /// An [`ErrorKind`] and optional string context
    Io(ErrorKind, Option<&'static str>),
    /// Packet was denied by a `Firewall`
    Firewall(filters::firewall::PacketDenied),
    Match(filters::r#match::Error),
    /// Packet was dropped by `Drop`
    Dropped,
    /// Packet exceeded the rate limit for the sending endpoint
    RateLimitExceeded,
    /// An error from a custom filter
    Custom(&'static str),
}

impl FilterError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Capture(cap) => cap.as_str(),
            Self::TokenRouter(tr) => tr.as_str(),
            Self::Compression(comp) => comp.as_str(),
            Self::Io(kind, _ctx) => io_kind_as_str(*kind),
            Self::Firewall(fw) => fw.as_str(),
            Self::Match(m) => m.as_str(),
            Self::Dropped => "dropped",
            Self::RateLimitExceeded => "rate limit exceeded",
            Self::Custom(custom) => custom,
        }
    }
}

impl std::error::Error for FilterError {}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capture(cap) => f.write_str(cap.as_str()),
            Self::TokenRouter(tr) => f.write_str(tr.as_str()),
            Self::Compression(comp) => write!(f, "{comp}"),
            Self::Io(kind, ctx) => {
                if let Some(ctx) = ctx {
                    write!(f, "io error - {kind}: {ctx}")
                } else {
                    write!(f, "io error - {kind}")
                }
            }
            Self::Firewall(fw) => f.write_str(fw.as_str()),
            Self::Match(m) => f.write_str(m.as_str()),
            Self::Dropped => f.write_str("dropped"),
            Self::RateLimitExceeded => f.write_str("rate limit exceeded"),
            Self::Custom(custom) => f.write_str(custom),
        }
    }
}

impl From<(std::io::Error, &'static str)> for FilterError {
    fn from((error, s): (std::io::Error, &'static str)) -> Self {
        Self::Io(error.kind(), Some(s))
    }
}

impl From<std::io::Error> for FilterError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind(), None)
    }
}

pub fn io_kind_as_str(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::AddrInUse => "address in use",
        ErrorKind::AddrNotAvailable => "address not available",
        ErrorKind::AlreadyExists => "already exists",
        ErrorKind::BrokenPipe => "broken pipe",
        ErrorKind::ConnectionAborted => "connection aborted",
        ErrorKind::ConnectionRefused => "connection refused",
        ErrorKind::ConnectionReset => "connection reset",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::InvalidData => "invalid data",
        ErrorKind::InvalidInput => "invalid input",
        ErrorKind::NotConnected => "not connected",
        ErrorKind::NotFound => "not found",
        ErrorKind::Other => "other",
        ErrorKind::OutOfMemory => "out of memory",
        ErrorKind::PermissionDenied => "permission denied",
        ErrorKind::TimedOut => "timed out",
        ErrorKind::UnexpectedEof => "unexpected eof",
        ErrorKind::Unsupported => "unsupported",
        ErrorKind::WouldBlock => "would block",
        ErrorKind::WriteZero => "write zero",
        _ => "unknown",
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
