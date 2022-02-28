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

use prometheus::{
    core::{AtomicU64, GenericCounter},
    exponential_buckets, Histogram, HistogramVec, IntCounterVec, Result as MetricsResult,
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

/// Start the histogram bucket at a quarter of a millisecond, as number below a millisecond are
/// what we are aiming for, but some granularity below a millisecond is useful for performance
/// profiling.
const BUCKET_START: f64 = 0.00025;

const BUCKET_FACTOR: f64 = 2.0;

/// At an exponential factor of 2.0 (BUCKET_FACTOR), 13 iterations gets us to just over 1 second.
/// Any processing that occurs over a second is far too long, so we end bucketing there as we don't
/// care about granularity past 1 second.
const BUCKET_COUNT: usize = 13;

impl Metrics {
    pub fn new() -> MetricsResult<Self> {
        let subsystem = "proxy";
        let event_labels = &[EVENT_LABEL];

        let processing_time = HistogramVec::new(
            histogram_opts(
                "packet_processing_duration_seconds",
                subsystem,
                "Total processing time for a packet",
                Some(exponential_buckets(BUCKET_START, BUCKET_FACTOR, BUCKET_COUNT).unwrap()),
            ),
            event_labels,
        )?
        .register_if_not_exists()?;

        Ok(Self {
            packets_dropped_no_endpoints: IntCounterVec::new(
                opts(
                    "packets_dropped_total",
                    subsystem,
                    "Total number of packets dropped by the proxy",
                ),
                &["reason"],
            )?
            .register_if_not_exists()?
            .get_metric_with_label_values(&["NoConfiguredEndpoints"])?,
            read_processing_time_seconds: processing_time
                .get_metric_with_label_values(&[EVENT_READ_LABEL_VALUE])?,
            write_processing_time_seconds: processing_time
                .get_metric_with_label_values(&[EVENT_WRITE_LABEL_VALUE])?,
        })
    }
}
