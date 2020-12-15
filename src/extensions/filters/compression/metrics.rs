/*
 * Copyright 2020 Google LLC All Rights Reserved.
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
use prometheus::core::{AtomicI64, GenericCounter, GenericGauge};
use prometheus::{IntCounterVec, Result as MetricsResult};
use prometheus::{IntGaugeVec, Registry};

use crate::metrics::{filter_opts, CollectorExt};

/// Register and manage metrics for this filter
pub(super) struct Metrics {
    pub(super) packets_dropped_compression: GenericCounter<AtomicI64>,
    pub(super) packets_dropped_decompression: GenericCounter<AtomicI64>,
    // Important to use a Gauge. Depending on compression algorithm, compressed values can be
    // larger than the original packets - so we want to be able to represent that via metrics.
    pub(super) bytes_diff_compression: GenericGauge<AtomicI64>,
    pub(super) bytes_diff_decompression: GenericGauge<AtomicI64>,
}

impl Metrics {
    pub(super) fn new(registry: &Registry) -> MetricsResult<Self> {
        let label_names = vec!["operation"];
        let dropped_metric = IntCounterVec::new(
            filter_opts(
                "packets_dropped",
                "Compression",
                "Total number of packets dropped as they could not be processed. labels: operation.",
            ),
            &label_names,
        )?
        .register(registry)?;

        let diff_metric = IntGaugeVec::new(
            filter_opts(
                "bytes_diff",
                "Compression",
                "Number of bytes difference between original and processed packet. \
                        Negative numbers indicate a packet growth. labels: operation.",
            ),
            &label_names,
        )?
        .register(registry)?;

        Ok(Metrics {
            packets_dropped_compression: dropped_metric
                .get_metric_with_label_values(vec!["Compression"].as_slice())?,
            packets_dropped_decompression: dropped_metric
                .get_metric_with_label_values(vec!["Decompression"].as_slice())?,
            bytes_diff_compression: diff_metric
                .get_metric_with_label_values(vec!["Compression"].as_slice())?,
            bytes_diff_decompression: diff_metric
                .get_metric_with_label_values(vec!["Decompression"].as_slice())?,
        })
    }
}
