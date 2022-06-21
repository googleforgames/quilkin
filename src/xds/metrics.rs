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

pub(crate) const CONTROL_PLANE_LABEL: &str = "control_plane";
pub(crate) const NODE_LABEL: &str = "node";
pub(crate) const TYPE_LABEL: &str = "type";

pub(crate) static ACTIVE_XDS_CLIENTS: Lazy<IntGaugeVec> = Lazy::new(|| {
    prometheus::register_int_gauge_vec_with_registry! {
        prometheus::opts! {
            "active_xds_clients",
            "Total number of active xDS clients",
        },
        &[NODE_LABEL],
        crate::metrics::registry(),
    }
    .unwrap()
});

pub(crate) static DISCOVERY_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
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

pub(crate) static ACKS: Lazy<IntCounterVec> = Lazy::new(|| {
    prometheus::register_int_counter_vec_with_registry! {
        prometheus::opts! {
            "xds_acks",
            "Total number of xDS ACKs",
        },
        &[NODE_LABEL, TYPE_LABEL],
        crate::metrics::registry(),
    }
    .unwrap()
});

pub(crate) static NACKS: Lazy<IntCounterVec> = Lazy::new(|| {
    prometheus::register_int_counter_vec_with_registry! {
        prometheus::opts! {
            "xds_nacks",
            "Total number of xDS NACKs",
        },
        &[NODE_LABEL, TYPE_LABEL],
        crate::metrics::registry(),
    }
    .unwrap()
});

pub struct StreamConnectionMetrics {
    node: String,
}

impl StreamConnectionMetrics {
    pub fn new(node: impl Into<String>) -> Self {
        let node = node.into();
        ACTIVE_XDS_CLIENTS.with_label_values(&[&*node]).inc();

        Self { node }
    }
}

impl Drop for StreamConnectionMetrics {
    fn drop(&mut self) {
        ACTIVE_XDS_CLIENTS.with_label_values(&[&*self.node]).dec();
    }
}
