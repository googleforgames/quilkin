/*
 * Copyright 2023 Google LLC
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

mod health;

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};

use self::health::Health;
use crate::config::Config;

use super::{agent, manage, proxy, relay};

pub const PORT: u16 = 8000;

pub(crate) const IDLE_REQUEST_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) const fn idle_request_interval_secs() -> u64 {
    IDLE_REQUEST_INTERVAL.as_secs()
}

/// The runtime mode of Quilkin, which contains various runtime configurations
/// specific to a mode.
#[derive(Clone, Debug)]
pub enum Admin {
    Proxy(proxy::RuntimeConfig),
    Relay(relay::RuntimeConfig),
    Manage(manage::RuntimeConfig),
    Agent(agent::RuntimeConfig),
}

impl Admin {
    #[track_caller]
    pub fn unwrap_agent(&self) -> &agent::RuntimeConfig {
        match self {
            Self::Agent(config) => config,
            _ => panic!("attempted to unwrap agent config when not in agent mode"),
        }
    }

    #[track_caller]
    pub fn unwrap_proxy(&self) -> &proxy::RuntimeConfig {
        match self {
            Self::Proxy(config) => config,
            _ => panic!("attempted to unwrap proxy config when not in proxy mode"),
        }
    }

    #[track_caller]
    pub fn unwrap_relay(&self) -> &relay::RuntimeConfig {
        match self {
            Self::Relay(config) => config,
            _ => panic!("attempted to unwrap relay config when not in relay mode"),
        }
    }

    #[track_caller]
    pub fn unwrap_manage(&self) -> &manage::RuntimeConfig {
        match self {
            Self::Manage(config) => config,
            _ => panic!("attempted to unwrap relay config when not in relay mode"),
        }
    }

    pub fn idle_request_interval(&self) -> Duration {
        match self {
            Self::Proxy(config) => config.idle_request_interval,
            Self::Agent(config) => config.idle_request_interval,
            Self::Relay(config) => config.idle_request_interval,
            _ => IDLE_REQUEST_INTERVAL,
        }
    }

    pub fn server(
        &self,
        config: Arc<Config>,
        address: Option<std::net::SocketAddr>,
    ) -> std::thread::JoinHandle<Result<(), hyper::Error>> {
        let address = address.unwrap_or_else(|| (std::net::Ipv6Addr::UNSPECIFIED, PORT).into());
        let health = Health::new();
        tracing::info!(address = %address, "Starting admin endpoint");

        let mode = self.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("couldn't create tokio runtime in thread");
            runtime.block_on(async move {
                let make_svc = make_service_fn(move |_conn| {
                    let config = config.clone();
                    let health = health.clone();
                    let mode = mode.clone();
                    async move {
                        let config = config.clone();
                        let health = health.clone();
                        let mode = mode.clone();
                        Ok::<_, Infallible>(service_fn(move |req| {
                            let config = config.clone();
                            let health = health.clone();
                            let mode = mode.clone();
                            async move { Ok::<_, Infallible>(mode.handle_request(req, config, health)) }
                        }))
                    }
                });

                HyperServer::bind(&address).serve(make_svc).await
            })
        })
    }

    fn is_ready(&self, config: &Config) -> bool {
        match &self {
            Self::Proxy(proxy) => proxy.is_ready(config),
            Self::Agent(agent) => agent.is_ready(),
            Self::Manage(manage) => manage.is_ready(),
            Self::Relay(relay) => relay.is_ready(),
        }
    }

    fn handle_request(
        &self,
        request: Request<Body>,
        config: Arc<Config>,
        health: Health,
    ) -> Response<Body> {
        match (request.method(), request.uri().path()) {
            (&Method::GET, "/metrics") => collect_metrics(),
            (&Method::GET, "/live" | "/livez") => health.check_liveness(),
            (&Method::GET, "/ready" | "/readyz") => check_readiness(|| self.is_ready(&config)),
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
}

fn check_readiness(check: impl Fn() -> bool) -> Response<Body> {
    if (check)() {
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
    use super::*;
    use crate::net::endpoint::Endpoint;

    #[tokio::test]
    async fn collect_metrics() {
        let response = super::collect_metrics();
        assert_eq!(response.status(), hyper::StatusCode::OK);
    }

    #[test]
    fn check_proxy_readiness() {
        let config = crate::Config::default();
        assert_eq!(config.clusters.read().endpoints().len(), 0);

        let admin = Admin::Proxy(<_>::default());
        assert!(!admin.is_ready(&config));

        config
            .clusters
            .write()
            .insert_default([Endpoint::new((std::net::Ipv4Addr::LOCALHOST, 25999).into())].into());

        assert!(admin.is_ready(&config));
    }
}
