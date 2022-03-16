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

use once_cell::sync::Lazy;

use prometheus::core::Collector;
pub use prometheus::Result;
use prometheus::{HistogramOpts, Opts, Registry, DEFAULT_BUCKETS};

/// "event" is used as a label for Metrics that can apply to both Filter
/// `read` and `write` executions.
pub const EVENT_LABEL: &str = "event";

/// Label value for [EVENT_LABEL] for `read` events
pub const EVENT_READ_LABEL_VALUE: &str = "read";
/// Label value for [EVENT_LABEL] for `write` events
pub const EVENT_WRITE_LABEL_VALUE: &str = "write";

/// Returns the [prometheus::Registry] containing all the metrics
/// registered in Quilkin.
pub fn registry() -> &'static Registry {
    static REGISTRY: Lazy<Registry> = Lazy::new(Registry::default);

    &*REGISTRY
}

/// Create a generic metrics options.
/// Use [filter_opts] instead if the intended target is a filter.
pub fn opts(name: &str, subsystem: &str, description: &str) -> Opts {
    Opts::new(name, description)
        .namespace("quilkin")
        .subsystem(subsystem)
}

pub fn histogram_opts(
    name: &str,
    subsystem: &str,
    description: &str,
    buckets: Option<Vec<f64>>,
) -> HistogramOpts {
    HistogramOpts {
        common_opts: opts(name, subsystem, description),
        buckets: buckets.unwrap_or_else(|| Vec::from(DEFAULT_BUCKETS as &'static [f64])),
    }
}

/// Create a generic metrics options for a filter.
pub fn filter_opts(name: &str, filter_name: &str, description: &str) -> Opts {
    opts(name, &format!("filter_{filter_name}"), description)
}

/// Registers the current metric collector with the provided registry.
/// Returns an error if a collector with the same name has already
/// been registered.
fn register_metric<T: Collector + Sized + 'static>(
    registry: &Registry,
    collector: T,
) -> Result<()> {
    registry.register(Box::new(collector))
}

pub trait CollectorExt: Collector + Clone + Sized + 'static {
    /// Registers the current metric collector with the provided registry
    /// if not already registered.
    fn register_if_not_exists(self) -> Result<Self> {
        match register_metric(crate::metrics::registry(), self.clone()) {
            Ok(_) | Err(prometheus::Error::AlreadyReg) => Ok(self),
            Err(err) => Err(err),
        }
    }
}

impl<C: Collector + Clone + 'static> CollectorExt for C {}
