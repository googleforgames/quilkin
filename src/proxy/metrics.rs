/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use crate::proxy::sessions::metrics::Metrics as SessionMetrics;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Response, Server as HyperServer, StatusCode};
use prometheus::{Encoder, Registry, Result as MetricsResult, TextEncoder};
use slog::{error, info, warn, Logger};
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::sync::watch::Receiver;

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
    mut shutdown_rx: Receiver<()>,
    log: Logger,
) {
    info!(log, "Starting metrics"; "address" => %addr);

    let handler_log = log.clone();
    let make_svc = make_service_fn(move |_conn| {
        let registry = registry.clone();
        let handler_log = handler_log.clone();
        async move {
            let registry = registry.clone();
            let handler_log = handler_log.clone();
            Ok::<_, Infallible>(service_fn(move |req| {
                let registry = registry.clone();
                let handler_log = handler_log.clone();
                async move {
                    Ok::<_, Infallible>(handle_request(
                        handler_log,
                        req.method(),
                        req.uri().path(),
                        registry,
                    ))
                }
            }))
        }
    });

    let server = HyperServer::bind(&addr)
        .serve(make_svc)
        .with_graceful_shutdown(async move {
            shutdown_rx.changed().await.ok();
        });

    tokio::spawn(async move {
        if let Err(err) = server.await {
            error!(log, "Metrics server exited with an error"; "error" => %err);
        }
    });
}

fn handle_request(log: Logger, method: &Method, path: &str, registry: Registry) -> Response<Body> {
    let mut response = Response::new(Body::empty());

    match (method, path) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let body = encoder
                .encode(&registry.gather(), &mut buffer)
                .map_err(|err| warn!(log, "Failed to encode metrics"; "error" => %err))
                .and_then(|_| {
                    String::from_utf8(buffer).map(Body::from).map_err(
                        |err| warn!(log, "Failed to convert metrics to utf8";  "error" => %err),
                    )
                });

            match body {
                Ok(body) => {
                    *response.body_mut() = body;
                }
                Err(_) => {
                    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                }
            }
        }
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };

    response
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
