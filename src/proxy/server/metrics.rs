/*
 * Copyright 2020 Google LLC
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

use prometheus::core::{AtomicU64, GenericCounter};
use prometheus::{
    exponential_buckets, Histogram, HistogramVec, IntCounterVec, Registry, Result as MetricsResult,
};

use crate::metrics::{
    histogram_opts, opts, CollectorExt, EVENT_LABEL, EVENT_READ_LABEL_VALUE,
    EVENT_WRITE_LABEL_VALUE,
};

#[derive(Clone)]
pub struct Metrics {
    pub packets_dropped_no_endpoints: GenericCounter<AtomicU64>,
    pub read_processing_time_seconds: Histogram,
    pub write_processing_time_seconds: Histogram,
}

impl Metrics {
    pub fn new(registry: &Registry) -> MetricsResult<Self> {
        let subsystem = "proxy";
        let event_labels = &[EVENT_LABEL];

        let processing_time = HistogramVec::new(
            histogram_opts(
                "processing_time_seconds",
                subsystem,
                "Total processing time for a packet",
                // Less than a millisecond is good, so starting at a quarter of that.
                // Any processing that goes over a second is way too long, so ending there.
                Some(exponential_buckets(0.00025, 2.0, 13).unwrap()),
            ),
            event_labels,
        )?
        .register_if_not_exists(registry)?;

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
            read_processing_time_seconds: processing_time
                .get_metric_with_label_values(&[EVENT_READ_LABEL_VALUE])?,
            write_processing_time_seconds: processing_time
                .get_metric_with_label_values(&[EVENT_WRITE_LABEL_VALUE])?,
        })
    }
}
