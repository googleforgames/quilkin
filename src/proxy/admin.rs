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
use slog::{error, info, o, Logger};
use tokio::sync::watch;

use crate::cluster::cluster_manager::SharedClusterManager;
use crate::filters::manager::SharedFilterManager;
use crate::proxy::{config_dump, Health, Metrics};

pub struct Admin {
    log: Logger,
    /// The address that the Admin server starts on
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    health: Arc<Health>,
}

#[derive(Clone)]
struct HandleRequestArgs {
    metrics: Arc<Metrics>,
    health: Arc<Health>,
    cluster_manager: SharedClusterManager,
    filter_manager: SharedFilterManager,
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

    pub(crate) fn run(
        &self,
        cluster_manager: SharedClusterManager,
        filter_manager: SharedFilterManager,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        info!(self.log, "Starting admin endpoint"; "address" => self.addr.to_string());

        let args = HandleRequestArgs {
            metrics: self.metrics.clone(),
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

        let log = self.log.clone();
        tokio::spawn(async move {
            if let Err(err) = server.await {
                error!(log, "Admin server exited with an error"; "error" => %err);
            }
        });
    }
}

fn handle_request(request: Request<Body>, args: HandleRequestArgs) -> Response<Body> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => args.metrics.collect_metrics(),
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
