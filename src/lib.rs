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

mod admin;
mod maxmind_db;
mod proxy;

pub(crate) mod metrics;
pub(crate) mod prost;
pub(crate) mod ttl_map;
pub(crate) mod utils;

pub mod cli;
pub mod cluster;
pub mod config;
pub mod endpoint;
pub mod filters;
pub mod metadata;
pub mod protocol;
pub mod xds;

#[doc(hidden)]
pub mod test_utils;

pub type Result<T, E = eyre::Error> = std::result::Result<T, E>;

#[doc(inline)]
pub use self::{
    cli::{Cli, Proxy},
    config::Config,
};

pub use quilkin_macros::include_proto;

pub(crate) use self::maxmind_db::MaxmindDb;

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
