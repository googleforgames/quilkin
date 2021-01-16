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
    pub(super) packets_dropped_compression: GenericCounter<AtomicI64>,
    pub(super) packets_dropped_decompression: GenericCounter<AtomicI64>,
    pub(super) received_compressed_bytes_total: GenericCounter<AtomicI64>,
    pub(super) received_expanded_bytes_total: GenericCounter<AtomicI64>,
    pub(super) sent_compressed_bytes_total: GenericCounter<AtomicI64>,
    pub(super) sent_expanded_bytes_total: GenericCounter<AtomicI64>,
}

impl Metrics {
    pub(super) fn new(registry: &Registry) -> MetricsResult<Self> {
        let operation_labels = vec!["operation"];
        let dropped_metric = IntCounterVec::new(
            filter_opts(
                "packets_dropped",
                "Compress",
                "Total number of packets dropped as they could not be processed. Labels: operation.",
            ),
            &operation_labels,
        )?
        .register(registry)?;

        let event_labels = vec!["event"];
        let expanded_bytes_total = IntCounterVec::new(
            filter_opts(
                "expanded_bytes_total",
                "Compress",
                "Total number of expanded bytes either received or sent. Labels: event",
            ),
            &event_labels,
        )?
        .register(registry)?;

        let compressed_bytes_total = IntCounterVec::new(
            filter_opts(
                "compressed_bytes_total",
                "Compress",
                "Total number of expanded bytes either received or sent. Labels: event",
            ),
            &event_labels,
        )?
        .register(registry)?;

        Ok(Metrics {
            packets_dropped_compression: dropped_metric
                .get_metric_with_label_values(vec!["Compression"].as_slice())?,
            packets_dropped_decompression: dropped_metric
                .get_metric_with_label_values(vec!["Decompression"].as_slice())?,
            received_compressed_bytes_total: compressed_bytes_total
                .get_metric_with_label_values(vec!["Received"].as_slice())?,
            received_expanded_bytes_total: expanded_bytes_total
                .get_metric_with_label_values(vec!["Received"].as_slice())?,
            sent_compressed_bytes_total: compressed_bytes_total
                .get_metric_with_label_values(vec!["Sent"].as_slice())?,
            sent_expanded_bytes_total: expanded_bytes_total
                .get_metric_with_label_values(vec!["Sent"].as_slice())?,
        })
    }
}
