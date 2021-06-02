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

mod cluster;
pub mod config;
pub mod extensions;
pub(crate) mod metrics;
pub mod proxy;
pub mod runner;
pub mod test_utils;
pub(crate) mod utils;
pub(crate) mod xds;

/// Run tests in our external documentation. This is only available in
/// nightly at the moment, but is stable on nightly and will be available in
/// 1.54.0. To run them locally run e.g `cargo +nightly test --doc`.
#[cfg(doctest)]
mod external_doc_tests {
    // HACK(XAMPPRocky): This is hidden inside a macro, because the right hand
    // side of `include_str!` is parsed before the `cfg` predicate currently.
    // https://github.com/rust-lang/rust/issues/85882
    macro_rules! hide {
        () => {
            #[doc = include_str!("../docs/extensions/filters/filters.md")]
            #[doc = include_str!("../docs/extensions/filters/writing_custom_filters.md")]
            #[doc = include_str!("../docs/extensions/filters/load_balancer.md")]
            #[doc = include_str!("../docs/extensions/filters/local_rate_limit.md")]
            #[doc = include_str!("../docs/extensions/filters/debug.md")]
            #[doc = include_str!("../docs/extensions/filters/concatenate_bytes.md")]
            #[doc = include_str!("../docs/extensions/filters/capture_bytes.md")]
            #[doc = include_str!("../docs/extensions/filters/token_router.md")]
            #[doc = include_str!("../docs/extensions/filters/compress.md")]
            mod tests {}
        };
    }

    hide!();
}
