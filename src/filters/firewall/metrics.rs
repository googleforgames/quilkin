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

use prometheus::{
    core::{AtomicU64, GenericCounter},
    IntCounterVec, Result as MetricsResult,
};

use crate::metrics::{
    filter_opts, CollectorExt, EVENT_LABEL, EVENT_READ_LABEL_VALUE, EVENT_WRITE_LABEL_VALUE,
};

/// Register and manage metrics for this filter
pub(super) struct Metrics {
    pub(super) packets_denied_read: GenericCounter<AtomicU64>,
    pub(super) packets_denied_write: GenericCounter<AtomicU64>,
    pub(super) packets_allowed_read: GenericCounter<AtomicU64>,
    pub(super) packets_allowed_write: GenericCounter<AtomicU64>,
}

impl Metrics {
    pub(super) fn new() -> MetricsResult<Self> {
        let event_labels = &[EVENT_LABEL];

        let deny_metric = IntCounterVec::new(
            filter_opts(
                "packets_denied_total",
                "Firewall",
                "Total number of packets denied. Labels: event.",
            ),
            event_labels,
        )?
        .register_if_not_exists()?;

        let allow_metric = IntCounterVec::new(
            filter_opts(
                "packets_allowed_total",
                "Firewall",
                "Total number of packets allowed. Labels: event.",
            ),
            event_labels,
        )?
        .register_if_not_exists()?;

        Ok(Metrics {
            packets_denied_read: deny_metric
                .get_metric_with_label_values(&[EVENT_READ_LABEL_VALUE])?,
            packets_denied_write: deny_metric
                .get_metric_with_label_values(&[EVENT_WRITE_LABEL_VALUE])?,
            packets_allowed_read: allow_metric
                .get_metric_with_label_values(&[EVENT_READ_LABEL_VALUE])?,
            packets_allowed_write: allow_metric
                .get_metric_with_label_values(&[EVENT_WRITE_LABEL_VALUE])?,
        })
    }
}
