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

use crate::metrics::{histogram_opts, opts, CollectorExt};
use prometheus::{
    core::{AtomicI64, AtomicU64, GenericCounter, GenericGauge},
    Histogram, IntCounter, IntGauge, Result as MetricsResult,
};

#[derive(Clone)]
pub struct Metrics {
    pub active_sessions: GenericGauge<AtomicI64>,
    pub sessions_total: GenericCounter<AtomicU64>,
    pub rx_bytes_total: GenericCounter<AtomicU64>,
    pub tx_bytes_total: GenericCounter<AtomicU64>,
    pub rx_packets_total: GenericCounter<AtomicU64>,
    pub tx_packets_total: GenericCounter<AtomicU64>,
    pub rx_errors_total: GenericCounter<AtomicU64>,
    pub tx_errors_total: GenericCounter<AtomicU64>,
    pub packets_dropped_total: GenericCounter<AtomicU64>,
    pub duration_secs: Histogram,
}

impl Metrics {
    pub fn new() -> MetricsResult<Self> {
        let subsystem = "session";
        Ok(Self {
            active_sessions: IntGauge::with_opts(opts(
                "active",
                subsystem,
                "Number of sessions currently active",
            ))?
            .register_if_not_exists()?,
            sessions_total: IntCounter::with_opts(opts(
                "total",
                subsystem,
                "Total number of established sessions",
            ))?
            .register_if_not_exists()?,
            rx_bytes_total: IntCounter::with_opts(opts(
                "rx_bytes_total",
                subsystem,
                "Total number of bytes received",
            ))?
            .register_if_not_exists()?,
            tx_bytes_total: IntCounter::with_opts(opts(
                "tx_bytes_total",
                subsystem,
                "Total number of bytes sent",
            ))?
            .register_if_not_exists()?,
            rx_packets_total: IntCounter::with_opts(opts(
                "rx_packets_total",
                subsystem,
                "Total number of packets received",
            ))?
            .register_if_not_exists()?,
            tx_packets_total: IntCounter::with_opts(opts(
                "tx_packets_total",
                subsystem,
                "Total number of packets sent",
            ))?
            .register_if_not_exists()?,
            packets_dropped_total: IntCounter::with_opts(opts(
                "packets_dropped_total",
                subsystem,
                "Total number of dropped packets",
            ))?
            .register_if_not_exists()?,
            rx_errors_total: IntCounter::with_opts(opts(
                "rx_errors_total",
                subsystem,
                "Total number of errors encountered while receiving a packet",
            ))?
            .register_if_not_exists()?,
            tx_errors_total: IntCounter::with_opts(opts(
                "tx_errors_total",
                subsystem,
                "Total number of errors encountered while sending a packet",
            ))?
            .register_if_not_exists()?,
            duration_secs: Histogram::with_opts(histogram_opts(
                "duration_secs",
                subsystem,
                "Duration of sessions",
                Some(vec![
                    1f64, 5f64, 10f64, 25f64, 60f64, 300f64, 900f64, 1800f64, 3600f64,
                ]),
            ))?
            .register_if_not_exists()?,
        })
    }
}
