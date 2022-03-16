/*
 * Copyright 2020 Google LLC
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

//! Filters for processing packets.

mod error;
mod factory;
mod read;
mod registry;
mod set;
mod write;

pub(crate) mod chain;

pub mod capture;
pub mod compress;
pub mod concatenate_bytes;
pub mod debug;
pub mod drop;
pub mod firewall;
pub mod load_balancer;
pub mod local_rate_limit;
pub mod r#match;
pub mod metadata;
pub mod pass;
pub mod token_router;

/// Prelude containing all types and traits required to implement [`Filter`] and
/// [`FilterFactory`].
pub mod prelude {
    pub use super::{
        ConvertProtoConfigError, CreateFilterArgs, DynFilterFactory, Error, Filter, FilterFactory,
        FilterInstance, ReadContext, ReadResponse, WriteContext, WriteResponse,
    };
}

// Core Filter types
pub use self::{
    error::{ConvertProtoConfigError, Error},
    factory::{CreateFilterArgs, DynFilterFactory, FilterFactory, FilterInstance},
    read::{ReadContext, ReadResponse},
    registry::FilterRegistry,
    set::{FilterMap, FilterSet},
    write::{WriteContext, WriteResponse},
};

pub(crate) use self::chain::{FilterChain, SharedFilterChain};

/// Trait for routing and manipulating packets.
///
/// An implementation of [`Filter`] provides a `read` and a `write` method. Both
/// methods are invoked by the proxy when it consults the filter chain - their
/// arguments contain information about the packet being processed.
/// - `read` is invoked when a packet is received on the local downstream port
///   and is to be sent to an upstream endpoint.
/// - `write` is invoked in the opposite direction when a packet is received
///   from an upstream endpoint and is to be sent to a downstream client.
///
/// **Metrics**
///
/// * `filter_read_duration_seconds` The duration it took for a `filter`'s
///   `read` implementation to execute.
///   * Labels
///     * `filter` The name of the filter being executed.
///
/// * `filter_write_duration_seconds` The duration it took for a `filter`'s
///   `write` implementation to execute.
///   * Labels
///     * `filter` The name of the filter being executed.
pub trait Filter: Send + Sync {
    /// [`Filter::read`] is invoked when the proxy receives data from a
    /// downstream connection on the listening port.
    ///
    /// This function should return a [`ReadResponse`] containing the array of
    /// endpoints that the packet should be sent to and the packet that should
    /// be sent (which may be manipulated) as well. If the packet should be
    /// rejected, return [`None`].  By default, the context passes
    /// through unchanged.
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        Some(ctx.into())
    }

    /// [`Filter::write`] is invoked when the proxy is about to send data to a
    /// downstream connection via the listening port after receiving it via one
    /// of the upstream Endpoints.
    ///
    /// This function should return an [`WriteResponse`] containing the packet to
    /// be sent (which may be manipulated). If the packet should be rejected,
    /// return [`None`]. By default, the context passes through unchanged.
    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        Some(ctx.into())
    }
}
