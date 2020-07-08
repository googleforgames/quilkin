use crate::server::sessions::metrics::Metrics as SessionMetrics;
use prometheus::{Encoder, Registry, Result as MetricsResult, TextEncoder};
use slog::{info, warn, Logger};
use std::net::SocketAddr;
use tokio::sync::oneshot::Receiver;
use warp::Filter as WarpFilter;

/// Metrics contains metrics configuration for the server.
#[derive(Clone)]
pub struct Metrics {
    /// addr is the socket address on which the server exposes metrics.
    /// If none is provided the server does not expose any metrics.
    pub addr: Option<SocketAddr>,
    pub registry: Registry,
}

/// start_metrics_server starts a HTTP server in the background at `addr` which
/// serves prometheus metrics from `registry`. The server is bounded by `shutdown_signal`,
pub fn start_metrics_server(
    addr: SocketAddr,
    registry: Registry,
    shutdown_signal: Receiver<()>,
    log: Logger,
) {
    info!(log, "starting metrics endpoint at {}", addr.to_string());

    let metrics_route = warp::path!("metrics").map(move || {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder
            .encode(&registry.gather(), &mut buffer)
            .map_err(|err| warn!(log, "failed to encode metrics: {:?}", err))
            .and_then(|_| {
                String::from_utf8(buffer).map_err(|err| {
                    warn!(log, "failed to convert metrics to utf8: {:?}", err);
                })
            })
            .unwrap_or("# failed to gather metrics".to_string())
    });

    let (_, server) = warp::serve(metrics_route).bind_with_graceful_shutdown(addr, async {
        shutdown_signal.await.ok();
    });

    tokio::spawn(server);
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new(None, Registry::default())
    }
}

impl Metrics {
    pub fn new(addr: Option<SocketAddr>, registry: Registry) -> Self {
        Metrics { addr, registry }
    }

    pub fn new_session_metrics(
        &self,
        downstream: &SocketAddr,
        upstream: &SocketAddr,
    ) -> MetricsResult<SessionMetrics> {
        SessionMetrics::new(
            &self.registry.clone(),
            downstream.to_string(),
            upstream.to_string(),
        )
    }
}
