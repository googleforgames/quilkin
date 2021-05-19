/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

mod config;
mod error;
mod factory;
mod read;
mod registry;
mod set;
mod write;

pub(crate) mod chain;
pub(crate) mod manager;

pub mod extensions;

/// Prelude containing all types and traits required to implement [`Filter`] and
/// [`FilterFactory`].
pub mod prelude {
    pub use super::{
        ConvertProtoConfigError, CreateFilterArgs, Error, Filter, FilterFactory, ReadContext,
        ReadResponse, WriteContext, WriteResponse,
    };
}

pub use self::{
    config::ConfigType,
    error::{ConvertProtoConfigError, Error},
    factory::{CreateFilterArgs, DynFilterFactory, FilterFactory},
    read::{ReadContext, ReadResponse},
    registry::FilterRegistry,
    set::{FilterMap, FilterSet},
    write::{WriteContext, WriteResponse},
};

pub(crate) use self::chain::FilterChain;

/// Filter is a trait for routing and manipulating packets.
pub trait Filter: Send + Sync {
    /// Read is invoked when the proxy receives data from a downstream connection on the
    /// listening port.
    /// This function should return a [`ReadResponse`] containing the array of
    /// endpoints that the packet should be sent to and the packet that should be
    /// sent (which may be manipulated) as well.
    /// If the packet should be rejected, return None.
    /// By default, passes the context through unchanged
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        Some(ctx.into())
    }

    /// Write is invoked when the proxy is about to send data to a downstream connection
    /// via the listening port after receiving it via one of the upstream Endpoints.
    /// This function should return an [`WriteResponse`] containing the packet to
    /// be sent (which may be manipulated).
    /// If the packet should be rejected, return None.
    /// By default, passes the context through unchanged
    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        Some(ctx.into())
    }
}
