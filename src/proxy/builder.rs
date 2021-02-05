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

use crate::config::{Config, ValidationError};
use crate::extensions::{default_registry, CreateFilterError, FilterChain, FilterRegistry};
use crate::proxy::server::metrics::Metrics as ProxyMetrics;
use crate::proxy::{Metrics, Server};
use slog::{o, Drain, Logger};
use std::{
    fmt::{self, Formatter},
    sync::Arc,
};

/// Represents an error that occurred while validating and building a server.
#[derive(Debug)]
pub enum Error {
    InvalidConfig(ValidationError),
    CreateFilterChain(CreateFilterError),
}

impl From<ValidationError> for Error {
    fn from(err: ValidationError) -> Self {
        Error::InvalidConfig(err)
    }
}

impl From<CreateFilterError> for Error {
    fn from(err: CreateFilterError) -> Self {
        Error::CreateFilterChain(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConfig(source) => write!(f, "invalid config: {}", format!("{}", source)),
            Error::CreateFilterChain(source) => write!(
                f,
                "failed to create filter chain: {}",
                format!("{}", source)
            ),
        }
    }
}

/// Marker representing whether or not a ServerBuilder has been
/// validated - If it hasn't been validated successfully, then
/// it is a compile error to build a server from it.
trait ValidationStatus {
    /// Output holds any intermediate result of validation.
    type Output;
}

/// Marks a ServerBuild as having validated successfully.
pub struct Validated(Arc<FilterChain>);
impl ValidationStatus for Validated {
    type Output = Arc<FilterChain>;
}

/// Marks a ServerBuild as not yet validated.
pub struct PendingValidation;
impl ValidationStatus for PendingValidation {
    type Output = ();
}

/// Represents the components needed to create a Server.
pub struct Builder<V> {
    log: Logger,
    config: Arc<Config>,
    filter_registry: FilterRegistry,
    metrics: Metrics,
    validation_status: V,
}

impl From<Arc<Config>> for Builder<PendingValidation> {
    fn from(config: Arc<Config>) -> Self {
        let log = logger();
        Builder {
            config,
            filter_registry: default_registry(&log),
            metrics: Metrics::default(),
            log,
            validation_status: PendingValidation,
        }
    }
}

impl Builder<PendingValidation> {
    pub fn with_log(self, log: Logger) -> Self {
        Self { log, ..self }
    }

    pub fn with_filter_registry(self, filter_registry: FilterRegistry) -> Self {
        Self {
            filter_registry,
            ..self
        }
    }

    pub fn with_metrics(self, metrics: Metrics) -> Self {
        Self { metrics, ..self }
    }

    // Validates the builder's config and filter configurations.
    pub fn validate(self) -> Result<Builder<Validated>, Error> {
        let _ = self.config.validate()?;
        let filter_chain = Arc::new(FilterChain::try_create(
            self.config.clone(),
            &self.filter_registry,
            &self.metrics.registry,
        )?);
        Ok(Builder {
            log: self.log,
            config: self.config,
            metrics: self.metrics,
            filter_registry: self.filter_registry,
            validation_status: Validated(filter_chain),
        })
    }
}

impl Builder<Validated> {
    pub fn build(self) -> Server {
        Server {
            log: self.log.new(o!("source" => "server::Server")),
            config: self.config,
            proxy_metrics: ProxyMetrics::new(&self.metrics.registry.clone())
                .expect("metrics should be setup properly"),
            metrics: self.metrics,
            filter_chain: self.validation_status.0,
            filter_registry: Arc::new(self.filter_registry),
        }
    }
}

pub fn logger() -> Logger {
    let drain = slog_json::Json::new(std::io::stdout())
        .set_pretty(false)
        .add_default_keys()
        .build()
        .fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}
