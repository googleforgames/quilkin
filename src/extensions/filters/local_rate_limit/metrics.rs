use crate::metrics::{filter_opts, CollectorExt};
use prometheus::core::{AtomicI64, GenericCounter};
use prometheus::Result as MetricsResult;
use prometheus::{IntCounter, Registry};

pub(super) struct Metrics {
    pub(super) packets_dropped_total: GenericCounter<AtomicI64>,
}

impl Metrics {
    pub(super) fn new(registry: &Registry) -> MetricsResult<Self> {
        Ok(Metrics {
            packets_dropped_total: IntCounter::with_opts(filter_opts(
                "packets_dropped",
                "LocalRateLimit",
                "Total number of packets dropped due to rate limiting",
            ))?
            .register(registry)?,
        })
    }
}
