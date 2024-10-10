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

use crate::net::maxmind_db::MetricsIpNetEntry;
use once_cell::sync::Lazy;
use prometheus::{
    core::Collector, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, DEFAULT_BUCKETS,
};

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

    #[inline]
    pub fn label(self) -> &'static str {
        match self {
            Self::Read => READ_DIRECTION_LABEL,
            Self::Write => WRITE_DIRECTION_LABEL,
        }
    }
}

pub struct AsnInfo<'a> {
    /// This is a 32-bit number, but there are only ~90000 asn's worldwide
    asn: [u8; 10],
    asn_len: u8,
    prefix: &'a str,
}

impl<'a> AsnInfo<'a> {
    #[inline]
    fn asn_str(&self) -> &str {
        // SAFETY: we only write ASCII in itoa
        unsafe { std::str::from_utf8_unchecked(&self.asn[..self.asn_len as _]) }
    }
}

pub const EMPTY: AsnInfo<'static> = AsnInfo {
    asn: [0u8; 10],
    asn_len: 0,
    prefix: "",
};

#[inline]
pub(crate) fn itoa(mut num: u64, asn: &mut [u8]) -> u8 {
    let mut index = 0;

    loop {
        let rem = (num % 10) as u8;
        asn[index] = rem + b'0';
        index += 1;
        num /= 10;

        if num == 0 {
            break;
        }
    }

    asn[..index].reverse();

    index as u8
}

impl<'a> From<Option<&'a MetricsIpNetEntry>> for AsnInfo<'a> {
    #[inline]
    fn from(value: Option<&'a MetricsIpNetEntry>) -> Self {
        let Some(val) = value else {
            return EMPTY;
        };

        let mut asn = [0u8; 10];
        let asn_len = itoa(val.id, &mut asn);

        Self {
            asn,
            asn_len,
            prefix: val.prefix.as_str(),
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

pub(crate) fn bytes_total(direction: Direction, asn: &AsnInfo) -> IntCounter {
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

    BYTES_TOTAL.with_label_values(&[direction.label(), asn.asn_str(), asn.prefix])
}

pub(crate) fn errors_total(direction: Direction, display: &str, asn: &AsnInfo) -> IntCounter {
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

    ERRORS_TOTAL.with_label_values(&[direction.label(), display, asn.asn_str(), asn.prefix])
}

pub(crate) fn packet_jitter(direction: Direction, asn: &AsnInfo) -> IntGauge {
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

    PACKET_JITTER.with_label_values(&[direction.label(), asn.asn_str(), asn.prefix])
}

pub(crate) fn packets_total(direction: Direction, asn: &AsnInfo) -> IntCounter {
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

    PACKETS_TOTAL.with_label_values(&[direction.label(), asn.asn_str(), asn.prefix])
}

pub(crate) fn packets_dropped_total(
    direction: Direction,
    source: &str,
    asn: &AsnInfo,
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

    PACKETS_DROPPED.with_label_values(&[direction.label(), source, asn.asn_str(), asn.prefix])
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

#[cfg(test)]
mod test {
    fn check(num: u64, exp: &str) {
        let mut asn = [0u8; 10];
        let len = super::itoa(num, &mut asn);

        // SAFETY: itoa only writes ASCII
        let asn_str = unsafe { std::str::from_utf8_unchecked(&asn[..len as _]) };

        assert_eq!(asn_str, exp);
    }

    #[test]
    fn itoa() {
        check(0, "0");
        check(1, "1");
        check(10, "10");
        check((u32::MAX >> 1) as _, &(u32::MAX >> 1).to_string());
        check((u32::MAX - 1) as _, &(u32::MAX - 1).to_string());
        check(u32::MAX as _, &u32::MAX.to_string());
    }
}
