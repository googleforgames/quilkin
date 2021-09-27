/*
 * Copyright 2021 Google LLC
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

use prometheus::core::{AtomicU64, GenericCounter};
use prometheus::{IntCounterVec, Registry, Result as MetricsResult};

use crate::metrics::{filter_opts, CollectorExt};

/// Register and manage metrics for this filter
pub(super) struct Metrics {
    pub(super) packets_denied_on_read: GenericCounter<AtomicU64>,
    pub(super) packets_denied_on_write: GenericCounter<AtomicU64>,
    pub(super) packets_allowed_on_read: GenericCounter<AtomicU64>,
    pub(super) packets_allowed_on_write: GenericCounter<AtomicU64>,
}

impl Metrics {
    pub(super) fn new(registry: &Registry) -> MetricsResult<Self> {
        let event_labels = vec!["events"];

        let deny_metric = IntCounterVec::new(
            filter_opts(
                "packets_denied_total",
                "Firewall",
                "Total number of packets denied. Labels: event.",
            ),
            &event_labels,
        )?
        .register_if_not_exists(registry)?;

        let allow_metric = IntCounterVec::new(
            filter_opts(
                "packets_allowed_total",
                "Firewall",
                "Total number of packets allowed. Labels: event.",
            ),
            &event_labels,
        )?
        .register_if_not_exists(registry)?;

        Ok(Metrics {
            packets_denied_on_read: deny_metric
                .get_metric_with_label_values(vec!["on_read"].as_slice())?,
            packets_denied_on_write: deny_metric
                .get_metric_with_label_values(vec!["on_write"].as_slice())?,
            packets_allowed_on_read: allow_metric
                .get_metric_with_label_values(vec!["on_read"].as_slice())?,
            packets_allowed_on_write: allow_metric
                .get_metric_with_label_values(vec!["on_write"].as_slice())?,
        })
    }
}
