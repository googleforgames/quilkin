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
use prometheus::core::{AtomicU64, GenericCounter};
use prometheus::{IntCounter, Registry};
use prometheus::{IntCounterVec, Result as MetricsResult};

use crate::metrics::{filter_opts, CollectorExt};

/// Register and manage metrics for this filter
pub(super) struct Metrics {
    pub(super) packets_dropped_compress: GenericCounter<AtomicU64>,
    pub(super) packets_dropped_decompress: GenericCounter<AtomicU64>,
    pub(super) compressed_bytes_total: GenericCounter<AtomicU64>,
    pub(super) decompressed_bytes_total: GenericCounter<AtomicU64>,
}

impl Metrics {
    pub(super) fn new(registry: &Registry) -> MetricsResult<Self> {
        let operation_labels = vec!["action"];
        let dropped_metric = IntCounterVec::new(
            filter_opts(
                "packets_dropped_total",
                "Compress",
                "Total number of packets dropped as they could not be processed. Labels: operation.",
            ),
            &operation_labels,
        )?
        .register(registry)?;

        let decompressed_bytes_total = IntCounter::with_opts(filter_opts(
            "decompressed_bytes_total",
            "Compress",
            "Total number of decompressed bytes either received or sent.",
        ))?
        .register(registry)?;

        let compressed_bytes_total = IntCounter::with_opts(filter_opts(
            "compressed_bytes_total",
            "Compress",
            "Total number of compressed bytes either received or sent.",
        ))?
        .register(registry)?;

        Ok(Metrics {
            packets_dropped_compress: dropped_metric
                .get_metric_with_label_values(vec!["Compress"].as_slice())?,
            packets_dropped_decompress: dropped_metric
                .get_metric_with_label_values(vec!["Decompress"].as_slice())?,
            compressed_bytes_total,
            decompressed_bytes_total,
        })
    }
}
