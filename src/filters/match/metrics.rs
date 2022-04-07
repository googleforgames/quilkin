/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::metrics::{filter_opts, CollectorExt};
use prometheus::{
    core::{AtomicU64, GenericCounter},
    IntCounter,
};

/// Register and manage metrics for this filter
pub struct Metrics {
    pub packets_matched_total: GenericCounter<AtomicU64>,
    pub packets_fallthrough_total: GenericCounter<AtomicU64>,
}

impl Metrics {
    pub(super) fn new() -> prometheus::Result<Self> {
        Ok(Metrics {
            packets_matched_total: IntCounter::with_opts(filter_opts(
                "packets_matched_total",
                "Match",
                "Total number of packets where the dynamic metadata matches a branch value.",
            ))?
            .register_if_not_exists()?,
            packets_fallthrough_total: IntCounter::with_opts(filter_opts(
                "packets_fallthrough_total",
                "Match",
                "Total number of packets that are processed by the fallthrough configuration",
            ))?
            .register_if_not_exists()?,
        })
    }
}
