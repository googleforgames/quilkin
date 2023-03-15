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

pub const PORT: u16 = 8000;

/// Define which mode Quilkin is in.
#[derive(Copy, Clone, Debug)]
pub enum Mode {
    Proxy,
    Xds,
}

pub fn server(
    mode: Mode,
    config: Arc<Config>,
    address: Option<std::net::SocketAddr>,
) -> tokio::task::JoinHandle<Result<(), hyper::Error>> {
    let address = address.unwrap_or_else(|| (std::net::Ipv6Addr::UNSPECIFIED, PORT).into());
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
                async move {
                    let result = handle_request(req, mode, config, health).await;
                    Ok::<_, Infallible>(map_result_into_response(result))
                }
            }))
        }
    });

    tokio::spawn(HyperServer::bind(&address).serve(make_svc))
}

/// Provides a generic way to map results into HTTP responses, providing it's
/// own 500 Response when it's `Err`, and passes the inner value if `Ok`.
fn map_result_into_response(request: Result<Response<Body>, eyre::Error>) -> Response<Body> {
    match request {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(%error, "admin http server error");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("internal error"))
                .unwrap()
        }
    }
}

#[tracing::instrument(skip_all, fields(method = %request.method(), path = %request.uri().path()))]
async fn handle_request(
    request: Request<Body>,
    mode: Mode,
    config: Arc<Config>,
    health: Health,
) -> Result<Response<Body>, eyre::Error> {
    tracing::trace!("handling request");

    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => Ok(collect_metrics()),
        (&Method::GET, "/debug/pprof/profile") => {
            let duration = request.uri().query().and_then(|query| {
                form_urlencoded::parse(query.as_bytes())
                    .find(|(k, _)| k == "seconds")
                    .and_then(|(_, v)| v.parse().ok())
                    .map(std::time::Duration::from_secs)
            });

            collect_pprof(duration).await
        }
        (&Method::GET, "/live" | "/livez") => Ok(health.check_healthy()),
        (&Method::GET, "/ready" | "/readyz") => Ok(match mode {
            Mode::Proxy => check_proxy_readiness(&config),
            Mode::Xds => health.check_healthy(),
        }),
        (&Method::GET, "/config") => Response::builder()
            .status(StatusCode::OK)
            .header(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            )
            .body(Body::from(serde_json::to_string(&config)?))
            .map_err(From::from),
        (_, path) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from(format!("{path} not found")))
            .map_err(From::from),
    }
}

fn check_proxy_readiness(config: &Config) -> Response<Body> {
    if config.clusters.read().endpoints().count() > 0 {
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

/// Collects profiling information using `prof` for an optional `duration` or
/// the default if `None`.
async fn collect_pprof(
    duration: Option<std::time::Duration>,
) -> Result<Response<Body>, eyre::Error> {
    let duration = duration.unwrap_or_else(|| std::time::Duration::from_secs(2));
    tracing::info!(duration_seconds = duration.as_secs(), "profiling");

    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(1000)
        // From the pprof docs, this blocklist helps prevent deadlock with
        // libgcc's unwind.
        .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()?;

    tokio::time::sleep(duration).await;

    let encoded_profile = crate::prost::encode(&guard.report().build()?.pprof()?)?;

    // gzip profile
    let mut encoder = libflate::gzip::Encoder::new(Vec::new())?;
    std::io::copy(&mut &encoded_profile[..], &mut encoder)?;
    let gzip_body = encoder.finish().into_result()?;
    tracing::info!("profile encoded to gzip");

    Response::builder()
        .header(hyper::header::CONTENT_LENGTH, gzip_body.len() as u64)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(gzip_body))
        .map_err(From::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::Endpoint;

    #[tokio::test]
    async fn collect_metrics() {
        let response = super::collect_metrics();
        assert_eq!(response.status(), hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn collect_pprof() {
        // Custom time to make the test fast.
        super::collect_pprof(Some(std::time::Duration::from_millis(1)))
            .await
            .unwrap();
    }

    #[test]
    fn check_proxy_readiness() {
        let config = Config::default();
        assert_eq!(config.clusters.read().endpoints().count(), 0);

        let response = super::check_proxy_readiness(&config);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        config
            .clusters
            .write()
            .insert_default([Endpoint::new((std::net::Ipv4Addr::LOCALHOST, 25999).into())].into());

        let response = super::check_proxy_readiness(&config);
        assert_eq!(response.status(), StatusCode::OK);
    }
}
