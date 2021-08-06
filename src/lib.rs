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

mod cluster;
pub mod config;
pub mod filters;
pub(crate) mod metrics;
mod proxy;
mod runner;
pub(crate) mod utils;
pub(crate) mod xds;

#[doc(hidden)]
pub mod test_utils;

pub type Result<T, E = runner::Error> = std::result::Result<T, E>;

#[doc(inline)]
pub use self::{
    config::Config,
    proxy::{logger, Builder, PendingValidation, Server, Validated},
    runner::{run, run_with_config},
};

pub use quilkin_macros::include_proto;

#[cfg(doctest)]
mod external_doc_tests {
    #![doc = include_str!("../docs/extensions/filters/filters.md")]
    #![doc = include_str!("../docs/extensions/filters/writing_custom_filters.md")]
    #![doc = include_str!("../docs/extensions/filters/load_balancer.md")]
    #![doc = include_str!("../docs/extensions/filters/local_rate_limit.md")]
    #![doc = include_str!("../docs/extensions/filters/debug.md")]
    #![doc = include_str!("../docs/extensions/filters/concatenate_bytes.md")]
    #![doc = include_str!("../docs/extensions/filters/capture_bytes.md")]
    #![doc = include_str!("../docs/extensions/filters/token_router.md")]
    #![doc = include_str!("../docs/extensions/filters/compress.md")]
}
