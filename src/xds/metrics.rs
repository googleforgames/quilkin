/*
 * Copyright 2021 Google LLC
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

use once_cell::sync::Lazy;
use prometheus::{IntCounterVec, IntGaugeVec};

pub(crate) const NODE_LABEL: &str = "node";
pub(crate) const CONTROL_PLANE_LABEL: &str = "control_plane";
pub(crate) const TYPE_LABEL: &str = "type";

pub(crate) fn active_control_planes(control_plane: &str) -> prometheus::IntGauge {
    static ACTIVE_CONTROL_PLANES: Lazy<IntGaugeVec> = Lazy::new(|| {
        prometheus::register_int_gauge_vec_with_registry! {
            prometheus::opts! {
                "active_control_planes",
                "Total number of active control plane connections",
            },
            &[CONTROL_PLANE_LABEL],
            crate::metrics::registry(),
        }
        .unwrap()
    });

    ACTIVE_CONTROL_PLANES.with_label_values(&[control_plane])
}

pub(crate) fn discovery_requests(node: &str, type_url: &str) -> prometheus::IntCounter {
    static DISCOVERY_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "discovery_requests",
                "Total number of xDS discovery requests",
            },
            &[NODE_LABEL, TYPE_LABEL],
            crate::metrics::registry(),
        }
        .unwrap()
    });

    DISCOVERY_REQUESTS.with_label_values(&[node, type_url])
}

pub(crate) fn discovery_responses(control_plane: &str, type_url: &str) -> prometheus::IntCounter {
    pub(crate) static DISCOVERY_RESPONSES: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "discovery_responses",
                "Total number of xDS discovery responses",
            },
            &[CONTROL_PLANE_LABEL, TYPE_LABEL],
            crate::metrics::registry(),
        }
        .unwrap()
    });

    DISCOVERY_RESPONSES.with_label_values(&[control_plane, type_url])
}

pub(crate) fn acks(control_plane: &str, type_url: &str) -> prometheus::IntCounter {
    static ACKS: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "xds_acks",
                "Total number of xDS ACKs",
            },
            &[CONTROL_PLANE_LABEL, TYPE_LABEL],
            crate::metrics::registry(),
        }
        .unwrap()
    });

    ACKS.with_label_values(&[control_plane, type_url])
}

pub(crate) fn nacks(control_plane: &str, type_url: &str) -> prometheus::IntCounter {
    static NACKS: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "xds_nacks",
                "Total number of xDS NACKs",
            },
            &[CONTROL_PLANE_LABEL, TYPE_LABEL],
            crate::metrics::registry(),
        }
        .unwrap()
    });

    NACKS.with_label_values(&[control_plane, type_url])
}

pub struct StreamConnectionMetrics {
    control_plane: String,
}

impl StreamConnectionMetrics {
    pub fn new(control_plane: String) -> Self {
        self::active_control_planes(&control_plane).inc();

        Self { control_plane }
    }
}

impl Drop for StreamConnectionMetrics {
    fn drop(&mut self) {
        self::active_control_planes(&self.control_plane).dec();
    }
}
