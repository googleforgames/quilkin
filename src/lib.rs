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

#![deny(unused_must_use)]

pub(crate) mod collections;
pub(crate) mod metrics;
pub mod pool;
pub mod time;

// Above other modules for thr `uring_spawn` macro.
#[macro_use]
pub mod net;

pub mod cli;
pub mod codec;
pub mod components;
pub mod config;
pub mod filters;

#[doc(hidden)]
pub mod test;

#[allow(
    clippy::enum_variant_names,
    clippy::large_enum_variant,
    rustdoc::bare_urls
)]
pub mod generated;

pub type Result<T, E = eyre::Error> = std::result::Result<T, E>;

#[doc(inline)]
pub use self::{
    cli::{Cli, Proxy},
    config::Config,
};

pub use quilkin_macros::include_proto;

pub(crate) use self::net::maxmind_db::MaxmindDb;

#[derive(Copy, Clone, PartialEq, Default, Debug)]
pub enum ShutdownKind {
    /// Normal shutdown kind, the receiver should perform proper shutdown procedures
    #[default]
    Normal,
    /// In a testing environment, some or all shutdown behavior may be skippable
    Testing,
    /// In a benching environment, some or all shutdown behavior may be skippable
    Benching,
}

/// Receiver for a shutdown event.
pub type ShutdownRx = tokio::sync::watch::Receiver<ShutdownKind>;
pub type ShutdownTx = tokio::sync::watch::Sender<ShutdownKind>;

#[inline]
pub fn make_shutdown_channel(init: ShutdownKind) -> (ShutdownTx, ShutdownRx) {
    tokio::sync::watch::channel(init)
}

/// A type which can be logged, usually error types.
pub(crate) trait Loggable {
    /// Output a log.
    fn log(&self);
}

#[cfg(doctest)]
mod external_doc_tests {
    #![doc = include_str!("../docs/src/services/proxy/filters.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/capture.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/compress.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/concatenate.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/debug.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/firewall.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/load_balancer.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/local_rate_limit.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/match.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/timestamp.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/token_router.md")]
    #![doc = include_str!("../docs/src/services/proxy/filters/writing_custom_filters.md")]
    #![doc = include_str!("../docs/src/services/xds/providers/filesystem.md")]
}
