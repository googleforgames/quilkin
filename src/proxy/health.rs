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

use std::sync::atomic::AtomicBool;

use hyper::{Body, Response, StatusCode};
use slog::{error, o, Logger};
use std::panic;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

pub struct Health {
    log: Logger,
    healthy: Arc<AtomicBool>,
}

impl Health {
    pub fn new(base: &Logger) -> Self {
        let health = Self {
            log: base.new(o!("source" => "proxy::Health")),
            healthy: Arc::new(AtomicBool::new(true)),
        };

        let log = health.log.clone();
        let healthy = health.healthy.clone();
        let default_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            error!(log, "Panic has occurred. Moving to Unhealthy");
            error!(log, "Info: {}", panic_info);
            healthy.swap(false, Relaxed);
            default_hook(panic_info);
        }));

        health
    }

    /// returns a HTTP 200 response if the proxy is healthy.
    pub fn check_healthy(&self) -> Response<Body> {
        if self.healthy.load(Relaxed) {
            return Response::new("ok".into());
        };

        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    }
}

#[cfg(test)]
mod tests {
    use crate::proxy::health::Health;
    use crate::test_utils::logger;
    use hyper::StatusCode;
    use std::panic;

    #[test]
    fn panic_hook() {
        let log = logger();
        let health = Health::new(&log);

        let response = health.check_healthy();
        assert_eq!(response.status(), StatusCode::OK);

        let _ = panic::catch_unwind(|| {
            panic!("oh no!");
        });

        let response = health.check_healthy();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
