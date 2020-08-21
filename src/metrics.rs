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

use prometheus::core::Collector;
pub use prometheus::Result;
use prometheus::{HistogramOpts, Opts, Registry, DEFAULT_BUCKETS};

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
    opts(name, &format!("filter_{}", filter_name), description)
}

pub trait CollectorExt: Collector + Clone + Sized + 'static {
    /// Registers the current metric collector with the provided registry.
    /// Returns an error if a collector with the same name has already
    /// been registered.
    fn register(self, registry: &Registry) -> Result<Self> {
        registry.register(Box::new(self.clone()))?;
        Ok(self)
    }

    /// Registers the current metric collector with the provided registry
    /// if not already registered.
    fn register_if_not_exists(self, registry: &Registry) -> Result<Self> {
        match self.clone().register(registry) {
            Ok(_) | Err(prometheus::Error::AlreadyReg) => Ok(self),
            Err(prometheus::Error::Msg(msg)) if msg.contains("already exists") => {
                // FIXME: We should be able to remove this branch entirely if `AlreadyReg` gets fixed.
                //  https://github.com/tikv/rust-prometheus/issues/247
                Ok(self)
            }
            Err(err) => Err(err),
        }
    }
}

impl<C: Collector + Clone + 'static> CollectorExt for C {}
