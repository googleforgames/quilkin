/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use crate::metrics::{opts, CollectorExt};
use prometheus::{
    core::{AtomicI64, GenericGauge},
    IntGauge, Result as MetricsResult,
};

#[derive(Clone)]
pub(super) struct Metrics {
    pub active_clusters: GenericGauge<AtomicI64>,
    pub active_endpoints: GenericGauge<AtomicI64>,
}

impl Metrics {
    pub fn new() -> MetricsResult<Self> {
        let subsystem = "cluster";
        Ok(Self {
            active_clusters: IntGauge::with_opts(opts(
                "active",
                subsystem,
                "Number of currently active clusters.",
            ))?
            .register_if_not_exists()?,
            active_endpoints: IntGauge::with_opts(opts(
                "active_endpoints",
                subsystem,
                "Number of currently active endpoints.",
            ))?
            .register_if_not_exists()?,
        })
    }
}
