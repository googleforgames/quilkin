/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use std::net::SocketAddr;

use prometheus::{Encoder, Registry, Result as MetricsResult, TextEncoder};
use slog::{info, warn, Logger};
use tokio::sync::oneshot::Receiver;
use tokio_compat_02::FutureExt;
use warp::Filter as WarpFilter;

use crate::proxy::sessions::metrics::Metrics as SessionMetrics;

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
pub async fn start_metrics_server(
    addr: SocketAddr,
    registry: Registry,
    shutdown_signal: Receiver<()>,
    log: Logger,
) {
    let log2 = log.clone();
    info!(log, "Starting metrics endpoint"; "addr" => addr.to_string());
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
            .unwrap_or_else(|_| "# failed to gather metrics".to_string())
    });

    let operation = async {
        let (_, server) = warp::serve(metrics_route).bind_with_graceful_shutdown(addr, async {
            shutdown_signal.await.ok();
        });

        let _ = tokio::spawn(server).compat().await;
    };

    info!(log2, ">>> start operation");
    operation.compat().await;
    info!(log2, ">>> return out of operation");
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
