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

// Fail the build if clippy finds any warnings.
#![deny(warnings)]
// Running external documentation tests depends on the
// `external_doc` unstable feature only available on a
// nightly compiler. So we enable the feature only when needed.
#![cfg_attr(doctest, feature(external_doc))]

mod cluster;
pub mod config;
pub mod extensions;
pub mod metrics;
pub mod proxy;
pub mod test_utils;
pub(crate) mod xds;

#[cfg(doctest)]
pub mod external_doc_tests {
    // Run tests in our external documentation.
    // Because this depends on the `external_doc` unstable feature,
    // it is only available using a nightly compiler.
    // To run them locally run e.g `cargo +nightly test --doc`
    #![doc(include = "../docs/extensions/filters/filters.md")]
    #![doc(include = "../docs/extensions/filters/local_rate_limit.md")]
    #![doc(include = "../docs/extensions/filters/debug.md")]
}
