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

use once_cell::sync::Lazy;
use prometheus::{
    core::Collector, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, DEFAULT_BUCKETS,
};

use crate::maxmind_db::IpNetEntry;

pub use prometheus::Result;

/// "event" is used as a label for Metrics that can apply to both Filter
/// `read` and `write` executions.
pub const DIRECTION_LABEL: &str = "event";

pub(crate) const READ: Direction = Direction::Read;
pub(crate) const WRITE: Direction = Direction::Write;
pub(crate) const ASN_LABEL: &str = "asn";
pub(crate) const PREFIX_LABEL: &str = "ip_prefix";

/// Label value for [DIRECTION_LABEL] for `read` events
pub const READ_DIRECTION_LABEL: &str = "read";
/// Label value for [DIRECTION_LABEL] for `write` events
pub const WRITE_DIRECTION_LABEL: &str = "write";

/// Returns the [prometheus::Registry] containing all the metrics
/// registered in Quilkin.
pub fn registry() -> &'static Registry {
    static REGISTRY: Lazy<Registry> =
        Lazy::new(|| Registry::new_custom(Some("quilkin".into()), None).unwrap());

    &REGISTRY
}

/// Start the histogram bucket at a quarter of a millisecond, as number below a millisecond are
/// what we are aiming for, but some granularity below a millisecond is useful for performance
/// profiling.
pub(crate) const BUCKET_START: f64 = 0.00025;

pub(crate) const BUCKET_FACTOR: f64 = 2.0;

/// At an exponential factor of 2.0 (BUCKET_FACTOR), 13 iterations gets us to just over 1 second.
/// Any processing that occurs over a second is far too long, so we end bucketing there as we don't
/// care about granularity past 1 second.
pub(crate) const BUCKET_COUNT: usize = 13;

#[derive(Clone, Copy, Debug)]
pub enum Direction {
    Read,
    Write,
}

impl Direction {
    pub(crate) const LABEL: &'static str = DIRECTION_LABEL;

    pub fn label(self) -> &'static str {
        match self {
            Self::Read => READ_DIRECTION_LABEL,
            Self::Write => WRITE_DIRECTION_LABEL,
        }
    }
}

pub(crate) fn processing_time(direction: Direction) -> Histogram {
    static PROCESSING_TIME: Lazy<HistogramVec> = Lazy::new(|| {
        prometheus::register_histogram_vec_with_registry! {
            prometheus::histogram_opts! {
                "packets_processing_duration_seconds",
                "Total processing time for a packet",
                prometheus::exponential_buckets(BUCKET_START, BUCKET_FACTOR, BUCKET_COUNT).unwrap(),
            },
            &[Direction::LABEL],
            registry(),
        }
        .unwrap()
    });

    PROCESSING_TIME.with_label_values(&[direction.label()])
}

pub(crate) fn bytes_total(direction: Direction, asn: Option<&IpNetEntry>) -> IntCounter {
    static BYTES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "bytes_total",
                "total number of bytes",
            },
            &[Direction::LABEL, ASN_LABEL, PREFIX_LABEL],
            registry(),
        }
        .unwrap()
    });

    BYTES_TOTAL.with_label_values(&[
        direction.label(),
        &asn.map(|asn| asn.r#as.to_string()).unwrap_or_default(),
        asn.map(|asn| &*asn.prefix).unwrap_or_default(),
    ])
}

pub(crate) fn errors_total(
    direction: Direction,
    display: &str,
    asn: Option<&IpNetEntry>,
) -> IntCounter {
    static ERRORS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "errors_total",
                "total number of errors sending packets",
            },
            &[Direction::LABEL, "display", ASN_LABEL, PREFIX_LABEL],
            registry(),
        }
        .unwrap()
    });

    ERRORS_TOTAL.with_label_values(&[
        direction.label(),
        display,
        &asn.map(|asn| asn.r#as.to_string()).unwrap_or_default(),
        asn.map(|asn| &*asn.prefix).unwrap_or_default(),
    ])
}

pub(crate) fn packet_jitter(direction: Direction, asn: Option<&IpNetEntry>) -> IntGauge {
    static PACKET_JITTER: Lazy<IntGaugeVec> = Lazy::new(|| {
        prometheus::register_int_gauge_vec_with_registry! {
            prometheus::opts! {
                "packet_jitter",
                "The time between new packets",
            },
            &[Direction::LABEL, ASN_LABEL, PREFIX_LABEL],
            registry(),
        }
        .unwrap()
    });

    PACKET_JITTER.with_label_values(&[
        direction.label(),
        &asn.map(|asn| asn.r#as.to_string()).unwrap_or_default(),
        asn.map(|asn| &*asn.prefix).unwrap_or_default(),
    ])
}

pub(crate) fn packets_total(direction: Direction, asn: Option<&IpNetEntry>) -> IntCounter {
    static PACKETS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "packets_total",
                "Total number of packets",
            },
            &[Direction::LABEL, ASN_LABEL, PREFIX_LABEL],
            registry(),
        }
        .unwrap()
    });

    PACKETS_TOTAL.with_label_values(&[
        direction.label(),
        &asn.map(|asn| asn.r#as.to_string()).unwrap_or_default(),
        asn.map(|asn| &*asn.prefix).unwrap_or_default(),
    ])
}

pub(crate) fn packets_dropped_total(
    direction: Direction,
    source: &str,
    asn: Option<&IpNetEntry>,
) -> IntCounter {
    static PACKETS_DROPPED: Lazy<IntCounterVec> = Lazy::new(|| {
        prometheus::register_int_counter_vec_with_registry! {
            prometheus::opts! {
                "packets_dropped_total",
                "Total number of dropped packets",
            },
            &[Direction::LABEL, "source", ASN_LABEL, PREFIX_LABEL],
            registry(),
        }
        .unwrap()
    });

    PACKETS_DROPPED.with_label_values(&[
        direction.label(),
        source,
        &asn.map(|asn| asn.r#as.to_string()).unwrap_or_default(),
        asn.map(|asn| &*asn.prefix).unwrap_or_default(),
    ])
}

/// Create a generic metrics options.
/// Use [filter_opts] instead if the intended target is a filter.
pub fn opts(name: &str, subsystem: &str, description: &str) -> Opts {
    Opts::new(name, description).subsystem(subsystem)
}

pub fn histogram_opts(
    name: &str,
    subsystem: &str,
    description: &str,
    buckets: impl Into<Option<Vec<f64>>>,
) -> HistogramOpts {
    HistogramOpts {
        common_opts: opts(name, subsystem, description),
        buckets: buckets
            .into()
            .unwrap_or_else(|| Vec::from(DEFAULT_BUCKETS as &'static [f64])),
    }
}

/// Registers the current metric collector with the provided registry.
///
/// # Panics
/// A collector with the same name has already been registered.
pub fn register<T: Collector + Sized + Clone + 'static>(collector: T) -> T {
    let return_value = collector.clone();

    self::registry()
        .register(Box::from(collector))
        .map(|_| return_value)
        .unwrap()
}

pub trait CollectorExt: Collector + Clone + Sized + 'static {
    /// Registers the current metric collector with the provided registry
    /// if not already registered.
    fn register_if_not_exists(self) -> Result<Self> {
        match registry().register(Box::from(self.clone())) {
            Ok(_) | Err(prometheus::Error::AlreadyReg) => Ok(self),
            Err(err) => Err(err),
        }
    }
}

impl<C: Collector + Clone + 'static> CollectorExt for C {}
