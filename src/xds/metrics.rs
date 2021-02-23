use crate::metrics::{opts, CollectorExt};
use prometheus::core::{AtomicI64, GenericCounter, GenericGauge};
use prometheus::Result as MetricsResult;
use prometheus::{IntCounter, Registry};

#[derive(Clone)]
pub struct Metrics {
    pub connected_state: GenericGauge<AtomicI64>,
    pub update_attempt_total: GenericCounter<AtomicI64>,
    pub update_success_total: GenericCounter<AtomicI64>,
    pub update_failure_total: GenericCounter<AtomicI64>,
    pub requests_total: GenericCounter<AtomicI64>,
}

impl Metrics {
    pub fn new(registry: &Registry) -> MetricsResult<Self> {
        let subsystem = "xds";
        Ok(Self {
            connected_state: GenericGauge::with_opts(
                opts("connected_state", subsystem, "A boolean that indicates the current connection state with the xDS management server."),
            )?.register_if_not_exists(registry)?,
            update_attempt_total: IntCounter::with_opts(
                opts("update_attempt_total", subsystem, "Total number of attempts made by the xDS management server to update resources."),
            )?
                .register_if_not_exists(registry)?,
            update_success_total: IntCounter::with_opts(
                opts("update_success_total", subsystem, "Total number of successful attempts made by the xDS management server to update resources."),
            )?
                .register_if_not_exists(registry)?,
            update_failure_total: IntCounter::with_opts(
                opts("update_failure_total", subsystem, "Total number of failed attempts made by the xDS management server to update resources."),
            )?
                .register_if_not_exists(registry)?,
            requests_total: IntCounter::with_opts(
                opts("requests_total", subsystem, "Total number of discovery requests made to the xDS management server."),
            )?
                .register_if_not_exists(registry)?,
        })
    }
}
