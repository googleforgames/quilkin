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
use prometheus::{Histogram, IntCounterVec, IntGauge, IntGaugeVec, Registry};

pub(crate) const NODE_LABEL: &str = "node";
pub(crate) const CONTROL_PLANE_LABEL: &str = "control_plane";
pub(crate) const TYPE_LABEL: &str = "type";

/// TODO: Remove and replace with a local registry.
static REGISTRY_ONCE: parking_lot::Once = parking_lot::Once::new();
static mut REGISTRY: Option<&'static Registry> = None;

/// Sets the [`Registry`] containing all the metrics registered in xDS.
pub fn set_registry(registry: &'static Registry) {
    REGISTRY_ONCE.call_once(|| unsafe {
        REGISTRY = Some(registry);
    });
}

/// Returns the [`Registry`] containing all the metrics registered in xDS.
#[inline]
pub fn registry() -> &'static Registry {
    unsafe { REGISTRY }.expect("set_registry must be called")
}

pub(crate) fn active_control_planes(control_plane: &str) -> IntGauge {
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

pub(crate) fn client_active(active: bool) {
    static METRIC: Lazy<IntGauge> = Lazy::new(|| {
        prometheus::register_int_gauge_with_registry! {
            prometheus::opts! {
                "provider_grpc_active",
                "Whether the gRPC configuration provider is active or not (either 1 or 0).",
            },
            registry(),
        }
        .unwrap()
    });

    METRIC.set(active as _);
}

pub(crate) fn client_connect_attempts_total(address: &impl std::fmt::Display) {
    static METRIC: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "provider_grpc_connect_attempts_total",
                "total number of attempts the gRPC provider has made to connect to `address`.",
            },
            &["address"],
            registry(),
        }
        .unwrap()
    });

    METRIC.with_label_values(&[&address.to_string()]).inc();
}

pub(crate) fn client_errors_total(reason: &impl std::fmt::Display) {
    static METRIC: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "provider_grpc_errors_total",
                "total number of errors the gRPC provider has encountered",
            },
            &["reason"],
            registry(),
        }
        .unwrap()
    });

    METRIC.with_label_values(&[&reason.to_string()]).inc();
}

pub fn client_connect_attempt_backoff_millis(delay: std::time::Duration) {
    pub(crate) const BUCKET_START: f64 = 0.001;
    pub(crate) const BUCKET_FACTOR: f64 = 2.0;
    pub(crate) const BUCKET_COUNT: usize = 13;

    static METRIC: Lazy<Histogram> = Lazy::new(|| {
        prometheus::register_histogram_with_registry! {
            prometheus::histogram_opts! {
                "provider_grpc_connect_attempt_backoff_seconds",
                "The backoff duration made when attempting reconnect to a gRPC provider",
                prometheus::exponential_buckets(BUCKET_START, BUCKET_FACTOR, BUCKET_COUNT).unwrap(),
            },
            registry(),
        }
        .unwrap()
    });

    METRIC.observe(delay.as_secs_f64());
}

pub(crate) fn server_active(active: bool) {
    static METRIC: Lazy<IntGauge> = Lazy::new(|| {
        prometheus::register_int_gauge_with_registry! {
            prometheus::opts! {
                "service_grpc_active",
                "Whether the gRPC service is active or not (either 1 or 0).",
            },
            registry(),
        }
        .unwrap()
    });

    METRIC.set(active as _);
}

pub(crate) fn server_resource_updates_total(resource: &str) {
    static METRIC: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "service_grpc_resource_updates_total",
                "total number of updates to a `resource` being sent to gRPC clients.",
            },
            &["address"],
            registry(),
        }
        .unwrap()
    });

    METRIC.with_label_values(&[resource]).inc();
}

pub(crate) fn delta_discovery_requests(node: &str, type_url: &str) -> prometheus::IntCounter {
    static DELTA_DISCOVERY_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "delta_discovery_requests",
                "Total number of xDS delta discovery requests",
            },
            &[NODE_LABEL, TYPE_LABEL],
            crate::metrics::registry(),
        }
        .unwrap()
    });

    DELTA_DISCOVERY_REQUESTS.with_label_values(&[node, type_url])
}

pub(crate) fn delta_discovery_responses(
    control_plane: &str,
    type_url: &str,
) -> prometheus::IntCounter {
    pub(crate) static DELTA_DISCOVERY_RESPONSES: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "delta_discovery_responses",
                "Total number of xDS delta discovery responses",
            },
            &[CONTROL_PLANE_LABEL, TYPE_LABEL],
            crate::metrics::registry(),
        }
        .unwrap()
    });

    DELTA_DISCOVERY_RESPONSES.with_label_values(&[control_plane, type_url])
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
