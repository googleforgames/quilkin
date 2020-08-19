/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use crate::metrics::{histogram_opts, opts, CollectorExt};
use prometheus::core::{AtomicI64, GenericCounter, GenericGauge};
use prometheus::{
    Histogram, HistogramVec, IntCounterVec, IntGaugeVec, Registry, Result as MetricsResult,
};

#[derive(Clone)]
pub struct Metrics {
    pub active_sessions: GenericGauge<AtomicI64>,
    pub sessions_total: GenericCounter<AtomicI64>,
    pub rx_bytes_total: GenericCounter<AtomicI64>,
    pub tx_bytes_total: GenericCounter<AtomicI64>,
    pub rx_packets_total: GenericCounter<AtomicI64>,
    pub tx_packets_total: GenericCounter<AtomicI64>,
    pub packets_dropped_total: GenericCounter<AtomicI64>,
    pub errors_total: GenericCounter<AtomicI64>,
    pub duration_secs: Histogram,
}

impl Metrics {
    pub fn new(registry: &Registry, downstream: String, upstream: String) -> MetricsResult<Self> {
        let subsystem = "session";
        let label_names = vec!["downstream", "upstream"];
        let label_values = vec![downstream.as_str(), upstream.as_str()];
        Ok(Self {
            active_sessions: IntGaugeVec::new(
                opts(
                    "active",
                    subsystem,
                    "Number of sessions currently active by downstream, upstream",
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
            sessions_total: IntCounterVec::new(
                opts(
                    "total",
                    subsystem,
                    "Total number of established sessions by downstream, upstream",
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
            rx_bytes_total: IntCounterVec::new(
                opts(
                    "rx_bytes_total",
                    subsystem,
                    "Total number of bytes received by downstream, upstream",
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
            tx_bytes_total: IntCounterVec::new(
                opts(
                    "tx_bytes_total",
                    subsystem,
                    "Total number of bytes sent by downstream, upstream",
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
            rx_packets_total: IntCounterVec::new(
                opts(
                    "rx_packets_total",
                    subsystem,
                    "Total number of packets received by downstream, upstream",
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
            tx_packets_total: IntCounterVec::new(
                opts(
                    "tx_packets_total",
                    subsystem,
                    "Total number of packets sent by downstream, upstream",
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
            packets_dropped_total: IntCounterVec::new(
                opts(
                    "packets_dropped_total",
                    subsystem,
                    "Total number of dropped packets by downstream, upstream",
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
            errors_total: IntCounterVec::new(
                opts(
                    "errors_total",
                    subsystem,
                    "Total number of errors during sending or receiving packets by downstream, upstream",
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
            duration_secs: HistogramVec::new(histogram_opts(
                "duration_secs",
                subsystem,
                "Duration of sessions by downstream, upstream",
                Some(vec![1f64, 5f64, 10f64, 25f64, 60f64, 300f64, 900f64, 1800f64, 3600f64]),
                ),
                &label_names,
            )?
            .register_if_not_exists(registry)?
            .get_metric_with_label_values(&label_values)?,
        })
    }
}
