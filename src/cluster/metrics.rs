use crate::metrics::{opts, CollectorExt};
use prometheus::core::{AtomicI64, GenericGauge};
use prometheus::Result as MetricsResult;
use prometheus::{IntGauge, Registry};

#[derive(Clone)]
pub(super) struct Metrics {
    pub active_clusters: GenericGauge<AtomicI64>,
    pub active_endpoints: GenericGauge<AtomicI64>,
}

impl Metrics {
    pub fn new(registry: &Registry) -> MetricsResult<Self> {
        let subsystem = "cluster";
        Ok(Self {
            active_clusters: IntGauge::with_opts(opts(
                "active",
                subsystem,
                "Number of currently active clusters.",
            ))?
            .register_if_not_exists(registry)?,
            active_endpoints: IntGauge::with_opts(opts(
                "active_endpoints",
                subsystem,
                "Number of currently active endpoints.",
            ))?
            .register_if_not_exists(registry)?,
        })
    }
}
