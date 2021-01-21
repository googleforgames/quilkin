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

use slog::Logger;

pub(crate) use filter_chain::CreateFilterError;
pub use filter_chain::FilterChain;
pub use filter_registry::{
    CreateFilterArgs, DownstreamContext, DownstreamResponse, Error, Filter, FilterFactory,
    FilterRegistry, UpstreamContext, UpstreamResponse,
};

pub(crate) mod filter_manager;
mod filter_registry;
pub mod filters;

mod filter_chain;

/// default_registry returns a FilterRegistry with the default
/// set of filters that are user configurable registered to it
pub fn default_registry(base: &Logger) -> FilterRegistry {
    let mut fr = FilterRegistry::default();
    fr.insert(filters::DebugFactory::new(base));
    fr.insert(filters::RateLimitFilterFactory::default());
    fr.insert(filters::ConcatBytesFactory::default());
    fr.insert(filters::LoadBalancerFilterFactory::default());
    fr.insert(filters::CaptureBytesFactory::new(base));
    fr.insert(filters::TokenRouterFactory::new(base));
    fr
}
