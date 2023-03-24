/*
 * Copyright 2020 Google LLC
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
use prometheus::{
    core::{AtomicU64, GenericCounter},
    IntCounter, Result as MetricsResult,
};

use crate::metrics::{filter_opts, CollectorExt};

/// Register and manage metrics for this filter
pub(super) struct Metrics {
    pub(super) compressed_bytes_total: GenericCounter<AtomicU64>,
    pub(super) decompressed_bytes_total: GenericCounter<AtomicU64>,
}

impl Metrics {
    pub(super) fn new() -> MetricsResult<Self> {
        let decompressed_bytes_total = IntCounter::with_opts(filter_opts(
            "decompressed_bytes_total",
            "Compress",
            "Total number of decompressed bytes either received or sent.",
        ))?
        .register_if_not_exists()?;

        let compressed_bytes_total = IntCounter::with_opts(filter_opts(
            "compressed_bytes_total",
            "Compress",
            "Total number of compressed bytes either received or sent.",
        ))?
        .register_if_not_exists()?;

        Ok(Metrics {
            compressed_bytes_total,
            decompressed_bytes_total,
        })
    }
}
