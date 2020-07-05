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
        buckets: buckets.unwrap_or(Vec::from(DEFAULT_BUCKETS as &'static [f64])),
    }
}

pub trait CollectorExt: Collector + Clone + Sized + 'static {
    fn register_if_not_exists(self, registry: &Registry) -> Result<Self> {
        match registry.register(Box::new(self.clone())) {
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
