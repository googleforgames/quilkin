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
    core::{AtomicU64, GenericCounter, GenericGauge},
    IntCounter, Result as MetricsResult,
};

#[derive(Clone)]
pub struct Metrics {
    pub connected_state: GenericGauge<AtomicU64>,
    pub update_attempt_total: GenericCounter<AtomicU64>,
    pub update_success_total: GenericCounter<AtomicU64>,
    pub update_failure_total: GenericCounter<AtomicU64>,
    pub requests_total: GenericCounter<AtomicU64>,
}

impl Metrics {
    pub fn new() -> MetricsResult<Self> {
        let subsystem = "xds";
        Ok(Self {
            connected_state: GenericGauge::with_opts(
                opts("connected_state", subsystem, "A boolean that indicates the current connection state with the xDS management server."),
            )?.register_if_not_exists()?,
            update_attempt_total: IntCounter::with_opts(
                opts("update_attempt_total", subsystem, "Total number of attempts made by the xDS management server to update resources."),
            )?
                .register_if_not_exists()?,
            update_success_total: IntCounter::with_opts(
                opts("update_success_total", subsystem, "Total number of successful attempts made by the xDS management server to update resources."),
            )?
                .register_if_not_exists()?,
            update_failure_total: IntCounter::with_opts(
                opts("update_failure_total", subsystem, "Total number of failed attempts made by the xDS management server to update resources."),
            )?
                .register_if_not_exists()?,
           requests_total: IntCounter::with_opts(
                opts("requests_total", subsystem, "Total number of discovery requests made to the xDS management server."),
            )?
                .register_if_not_exists()?,
        })
    }
}
