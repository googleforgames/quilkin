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

mod health;

use std::convert::Infallible;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};

use self::health::Health;
use crate::config::Config;

pub fn server(config: Arc<Config>) -> tokio::task::JoinHandle<Result<(), hyper::Error>> {
    let address = config.admin.load().address;
    let health = Health::new();
    tracing::info!(address = %address, "Starting admin endpoint");

    let make_svc = make_service_fn(move |_conn| {
        let config = config.clone();
        let health = health.clone();
        async move {
            let config = config.clone();
            let health = health.clone();
            Ok::<_, Infallible>(service_fn(move |req| {
                let config = config.clone();
                let health = health.clone();
                async move { Ok::<_, Infallible>(handle_request(req, config, health)) }
            }))
        }
    });

    tokio::spawn(HyperServer::bind(&address).serve(make_svc))
}

fn handle_request(request: Request<Body>, config: Arc<Config>, health: Health) -> Response<Body> {
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => collect_metrics(),
        (&Method::GET, "/live" | "/livez") => health.check_healthy(),
        (&Method::GET, "/ready" | "/readyz") => check_readiness(&config),
        (&Method::GET, "/config") => match serde_json::to_string(&config) {
            Ok(body) => Response::builder()
                .status(StatusCode::OK)
                .header(
                    "Content-Type",
                    hyper::header::HeaderValue::from_static("application/json"),
                )
                .body(Body::from(body))
                .unwrap(),
            Err(err) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("failed to create config dump: {err}")))
                .unwrap(),
        },
        (_, _) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        }
    }
}

fn check_readiness(config: &Config) -> Response<Body> {
    if config.clusters.load().endpoints().count() > 0 {
        return Response::new("ok".into());
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
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
