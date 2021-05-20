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

use hyper::{Body, Response, StatusCode};
use prometheus::{Encoder, Registry, Result as MetricsResult, TextEncoder};
use slog::{o, warn, Logger};

use crate::proxy::sessions::metrics::Metrics as SessionMetrics;

/// Metrics contains metrics configuration for the server.
#[derive(Clone)]
pub struct Metrics {
    log: Logger,
    pub(crate) registry: Registry,
}

impl Metrics {
    pub fn new(base: &Logger, registry: Registry) -> Self {
        Metrics {
            log: base.new(o!("source" => "proxy::Metrics")),
            registry,
        }
    }

    pub fn new_session_metrics(&self) -> MetricsResult<SessionMetrics> {
        SessionMetrics::new(&self.registry.clone())
    }

    pub fn collect_metrics(&self) -> Response<Body> {
        let mut response = Response::new(Body::empty());
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let body = encoder
            .encode(&self.registry.gather(), &mut buffer)
            .map_err(|err| warn!(self.log, "Failed to encode metrics"; "error" => %err))
            .and_then(|_| {
                String::from_utf8(buffer).map(Body::from).map_err(
                    |err| warn!(self.log, "Failed to convert metrics to utf8"; "error" => %err),
                )
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
}

#[cfg(test)]
mod tests {
    use hyper::StatusCode;
    use prometheus::Registry;

    use crate::proxy::Metrics;
    use crate::test_utils::logger;

    #[tokio::test]
    async fn collect_metrics() {
        let log = logger();
        let metrics = Metrics::new(&log, Registry::default());
        let response = metrics.collect_metrics();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
