/*
 * Copyright 2021 Google LLC All Rights Reserved.
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

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};
use slog::{error, info, o, Logger};
use tokio::sync::watch;

use crate::proxy::{Health, Metrics};

pub struct Admin {
    log: Logger,
    /// The address that the Admin server starts on
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    health: Arc<Health>,
}

impl Admin {
    pub fn new(base: &Logger, addr: SocketAddr, metrics: Arc<Metrics>, heath: Health) -> Self {
        Admin {
            log: base.new(o!("source" => "proxy::Admin")),
            addr,
            metrics,
            health: Arc::new(heath),
        }
    }

    pub fn run(&self, mut shutdown_rx: watch::Receiver<()>) {
        info!(self.log, "Starting admin endpoint"; "address" => self.addr.to_string());

        let metrics = self.metrics.clone();
        let health = self.health.clone();
        let make_svc = make_service_fn(move |_conn| {
            let metrics = metrics.clone();
            let health = health.clone();
            async move {
                let metrics = metrics.clone();
                let health = health.clone();
                Ok::<_, Infallible>(service_fn(move |req| {
                    let metrics = metrics.clone();
                    let health = health.clone();
                    async move { Ok::<_, Infallible>(handle_request(req, metrics, health)) }
                }))
            }
        });

        let server = HyperServer::bind(&self.addr)
            .serve(make_svc)
            .with_graceful_shutdown(async move {
                shutdown_rx.changed().await.ok();
            });

        let log = self.log.clone();
        tokio::spawn(async move {
            if let Err(err) = server.await {
                error!(log, "Admin server exited with an error"; "error" => %err);
            }
        });
    }
}

fn handle_request(
    request: Request<Body>,
    metrics: Arc<Metrics>,
    health: Arc<Health>,
) -> Response<Body> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => metrics.collect_metrics(),
        (&Method::GET, "/live") => health.check_healthy(),
        (_, _) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        }
    }
}
