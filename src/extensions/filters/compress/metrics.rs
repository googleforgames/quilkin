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
use prometheus::core::{AtomicI64, GenericCounter};
use prometheus::Registry;
use prometheus::{IntCounterVec, Result as MetricsResult};

use crate::metrics::{filter_opts, CollectorExt};

/// Register and manage metrics for this filter
pub(super) struct Metrics {
    pub(super) packets_dropped_compress: GenericCounter<AtomicI64>,
    pub(super) packets_dropped_decompress: GenericCounter<AtomicI64>,
    pub(super) received_compressed_bytes_total: GenericCounter<AtomicI64>,
    pub(super) received_decompressed_bytes_total: GenericCounter<AtomicI64>,
    pub(super) sent_compressed_bytes_total: GenericCounter<AtomicI64>,
    pub(super) sent_decompressed_bytes_total: GenericCounter<AtomicI64>,
}

impl Metrics {
    pub(super) fn new(registry: &Registry) -> MetricsResult<Self> {
        let operation_labels = vec!["operation"];
        let dropped_metric = IntCounterVec::new(
            filter_opts(
                "packets_dropped_total",
                "Compress",
                "Total number of packets dropped as they could not be processed. Labels: operation.",
            ),
            &operation_labels,
        )?
        .register(registry)?;

        let event_labels = vec!["event"];
        let decompressed_bytes_total = IntCounterVec::new(
            filter_opts(
                "decompressed_bytes_total",
                "Compress",
                "Total number of bytes after being decompressed when received or sent. Labels: event",
            ),
            &event_labels,
        )?
        .register(registry)?;

        let compressed_bytes_total = IntCounterVec::new(
            filter_opts(
                "compressed_bytes_total",
                "Compress",
                "Total number of bytes after being compressed when received or sent. Labels: event",
            ),
            &event_labels,
        )?
        .register(registry)?;

        Ok(Metrics {
            packets_dropped_compress: dropped_metric
                .get_metric_with_label_values(vec!["Compress"].as_slice())?,
            packets_dropped_decompress: dropped_metric
                .get_metric_with_label_values(vec!["Decompress"].as_slice())?,
            received_compressed_bytes_total: compressed_bytes_total
                .get_metric_with_label_values(vec!["Received"].as_slice())?,
            received_decompressed_bytes_total: decompressed_bytes_total
                .get_metric_with_label_values(vec!["Received"].as_slice())?,
            sent_compressed_bytes_total: compressed_bytes_total
                .get_metric_with_label_values(vec!["Sent"].as_slice())?,
            sent_decompressed_bytes_total: decompressed_bytes_total
                .get_metric_with_label_values(vec!["Sent"].as_slice())?,
        })
    }
}
