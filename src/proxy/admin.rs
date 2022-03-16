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

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};
use tokio::sync::watch;

use crate::cluster::SharedCluster;
use crate::filters::SharedFilterChain;
use crate::proxy::{config_dump, Health};

pub struct Admin {
    /// The address that the Admin server starts on
    addr: SocketAddr,
    health: Arc<Health>,
}

#[derive(Clone)]
struct HandleRequestArgs {
    health: Arc<Health>,
    cluster_manager: SharedCluster,
    filter_manager: SharedFilterChain,
}

impl Admin {
    pub fn new(addr: SocketAddr, health: Health) -> Self {
        Admin {
            addr,
            health: Arc::new(health),
        }
    }

    pub(crate) fn run(
        &self,
        cluster_manager: SharedCluster,
        filter_manager: SharedFilterChain,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        tracing::info!(address = %self.addr, "Starting admin endpoint");

        let args = HandleRequestArgs {
            health: self.health.clone(),
            cluster_manager,
            filter_manager,
        };
        let make_svc = make_service_fn(move |_conn| {
            let args = args.clone();
            async move {
                let args = args.clone();
                Ok::<_, Infallible>(service_fn(move |req| {
                    let args = args.clone();
                    async move { Ok::<_, Infallible>(handle_request(req, args)) }
                }))
            }
        });

        let server = HyperServer::bind(&self.addr)
            .serve(make_svc)
            .with_graceful_shutdown(async move {
                shutdown_rx.changed().await.ok();
            });

        tokio::spawn(async move {
            if let Err(error) = server.await {
                tracing::error!(%error, "Admin server exited with an error");
            }
        });
    }
}

fn handle_request(request: Request<Body>, args: HandleRequestArgs) -> Response<Body> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => collect_metrics(),
        (&Method::GET, "/live") => args.health.check_healthy(),
        (&Method::GET, "/config") => {
            config_dump::handle_request(args.cluster_manager, args.filter_manager)
        }
        (_, _) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        }
    }
}

fn collect_metrics() -> Response<Body> {
    let mut response = Response::new(Body::empty());
    let mut buffer = vec![];
    let encoder = prometheus::TextEncoder::new();
    let body =
        prometheus::Encoder::encode(&encoder, &crate::metrics::registry().gather(), &mut buffer)
            .map_err(|error| tracing::warn!(%error, "Failed to encode metrics"))
            .and_then(|_| {
                String::from_utf8(buffer)
                    .map(Body::from)
                    .map_err(|error| tracing::warn!(%error, "Failed to convert metrics to utf8"))
            });

    match body {
        Ok(body) => {
            *response.body_mut() = body;
        }
        Err(_) => {
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    response
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn collect_metrics() {
        let response = super::collect_metrics();
        assert_eq!(response.status(), hyper::StatusCode::OK);
    }
}
