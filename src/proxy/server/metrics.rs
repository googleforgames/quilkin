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

use crate::metrics::{opts, CollectorExt};
use prometheus::core::{AtomicU64, GenericCounter};
use prometheus::{IntCounterVec, Registry, Result as MetricsResult};

#[derive(Clone)]
pub struct Metrics {
    pub packets_dropped_no_endpoints: GenericCounter<AtomicU64>,
}

impl Metrics {
    pub fn new(registry: &Registry) -> MetricsResult<Self> {
        let subsystem = "proxy";
        Ok(Self {
            packets_dropped_no_endpoints: IntCounterVec::new(
                opts(
                    "packets_dropped_total",
                    subsystem,
                    "Total number of packets dropped by the proxy",
                ),
                &["reason"],
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&["NoConfiguredEndpoints"])?,
        })
    }
}
