/*
 * Copyright 2020 Google LLC
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

use std::{collections::HashSet, convert::TryInto, marker::PhantomData, sync::Arc};

use prometheus::Registry;
use slog::{o, Drain, Logger};
use tonic::transport::Endpoint as TonicEndpoint;

use crate::config::{Config, ManagementServer, Proxy, Source, ValidationError, ValueInvalidArgs};
use crate::endpoint::Endpoints;
use crate::filters::{chain::Error as FilterChainError, FilterChain, FilterRegistry, FilterSet};
use crate::proxy::server::metrics::Metrics as ProxyMetrics;
use crate::proxy::sessions::metrics::Metrics as SessionMetrics;
use crate::proxy::{Admin as ProxyAdmin, Health, Metrics, Server};

pub(super) enum ValidatedSource {
    Static {
        filter_chain: Arc<FilterChain>,
        endpoints: Endpoints,
    },
    Dynamic {
        management_servers: Vec<ManagementServer>,
    },
}

pub(super) struct ValidatedConfig {
    pub proxy: Proxy,
    pub source: ValidatedSource,
    // Limit struct creation to the builder.
    pub phantom: PhantomData<()>,
}

/// Represents an error that occurred while validating and building a server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid config: {}", .0)]
    InvalidConfig(ValidationError),
    #[error("failed to create filter chain: {}", .0)]
    CreateFilterChain(FilterChainError),
}

impl From<ValidationError> for Error {
    fn from(err: ValidationError) -> Self {
        Error::InvalidConfig(err)
    }
}

impl From<FilterChainError> for Error {
    fn from(err: FilterChainError) -> Self {
        Error::CreateFilterChain(err)
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
pub struct Validated(ValidatedConfig);
impl ValidationStatus for Validated {
    type Output = ValidatedConfig;
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
    admin: Option<ProxyAdmin>,
    metrics: Arc<Metrics>,
    validation_status: V,
}

impl From<Arc<Config>> for Builder<PendingValidation> {
    fn from(config: Arc<Config>) -> Self {
        let log = logger();
        let metrics = Arc::new(Metrics::new(&log, Registry::default()));
        let health = Health::new(&log);
        let admin = ProxyAdmin::new(&log, config.admin.address, metrics.clone(), health);
        Builder {
            config,
            filter_registry: FilterRegistry::new(FilterSet::default(&log)),
            admin: Some(admin),
            metrics,
            log,
            validation_status: PendingValidation,
        }
    }
}

impl ValidatedConfig {
    fn validate(
        config: Arc<Config>,
        filter_registry: &FilterRegistry,
        metrics: &Metrics,
    ) -> Result<Self, Error> {
        let validated_source = match &config.source {
            Source::Static {
                filters,
                endpoints: config_endpoints,
            } => {
                if config_endpoints
                    .iter()
                    .map(|ep| ep.address)
                    .collect::<HashSet<_>>()
                    .len()
                    != config_endpoints.len()
                {
                    return Err(
                        ValidationError::NotUnique("static.endpoints.address".to_string()).into(),
                    );
                }

                let endpoints = Endpoints::new(config_endpoints.clone())
                    .ok_or_else(|| ValidationError::EmptyList("static.endpoints".into()))?;

                ValidatedSource::Static {
                    filter_chain: Arc::new(FilterChain::try_create(
                        filters.clone(),
                        filter_registry,
                        &metrics.registry,
                    )?),
                    endpoints,
                }
            }
            Source::Dynamic { management_servers } => {
                if management_servers.is_empty() {
                    return Err(ValidationError::EmptyList(
                        "dynamic.management_servers".to_string(),
                    )
                    .into());
                }

                if management_servers
                    .iter()
                    .map(|server| &server.address)
                    .collect::<HashSet<_>>()
                    .len()
                    != management_servers.len()
                {
                    return Err(ValidationError::NotUnique(
                        "dynamic.management_servers.address".to_string(),
                    )
                    .into());
                }

                for server in management_servers {
                    let res: Result<TonicEndpoint, _> = server.address.clone().try_into();
                    if res.is_err() {
                        return Err(ValidationError::ValueInvalid(ValueInvalidArgs {
                            field: "dynamic.management_servers.address".into(),
                            clarification: Some("the provided value must be a valid URI".into()),
                            examples: Some(vec![
                                "http://127.0.0.1:8080".into(),
                                "127.0.0.1:8081".into(),
                                "example.com".into(),
                            ]),
                        })
                        .into());
                    }
                }

                ValidatedSource::Dynamic {
                    management_servers: management_servers.clone(),
                }
            }
        };

        Ok(ValidatedConfig {
            proxy: config.proxy.clone(),
            source: validated_source,
            phantom: Default::default(),
        })
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

    /// Disable the admin interface
    pub fn disable_admin(self) -> Self {
        Self {
            admin: None,
            ..self
        }
    }

    // Validates the builder's config and filter configurations.
    pub fn validate(self) -> Result<Builder<Validated>, Error> {
        let validated_config =
            ValidatedConfig::validate(self.config.clone(), &self.filter_registry, &self.metrics)?;

        Ok(Builder {
            log: self.log,
            config: self.config,
            admin: self.admin,
            metrics: self.metrics,
            filter_registry: self.filter_registry,
            validation_status: Validated(validated_config),
        })
    }
}

impl Builder<Validated> {
    pub fn build(self) -> Server {
        Server {
            log: self.log.new(o!("source" => "server::Server")),
            config: Arc::new(self.validation_status.0),
            proxy_metrics: ProxyMetrics::new(&self.metrics.registry)
                .expect("proxy metrics should be setup properly"),
            session_metrics: SessionMetrics::new(&self.metrics.registry)
                .expect("session metrics should be setup properly"),
            admin: self.admin,
            metrics: self.metrics,
            filter_registry: self.filter_registry,
        }
    }
}

/// Create a new `slog::Logger` instance using the default
/// quilkin configuration.
pub fn logger() -> Logger {
    let drain = slog_json::Json::new(std::io::stdout())
        .set_pretty(false)
        .add_default_keys()
        .build()
        .fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::sync::Arc;

    use crate::config::{Config, ValidationError};
    use crate::proxy::builder::Validated;

    use super::{Builder, Error};

    #[track_caller]
    fn parse_config(yaml: &str) -> Config {
        Config::from_reader(yaml.as_bytes()).unwrap()
    }

    fn validate_unwrap_ok(yaml: &'static str) -> Builder<Validated> {
        Builder::try_from(Arc::new(parse_config(yaml)))
            .unwrap()
            .validate()
            .unwrap()
    }

    #[track_caller]
    fn validate_unwrap_err(yaml: &'static str) -> ValidationError {
        match Builder::try_from(Arc::new(parse_config(yaml)))
            .unwrap()
            .validate()
        {
            Err(Error::InvalidConfig(err)) => err,
            Err(err) => unreachable!(format!("expected ValidationError, got {}", err)),
            Ok(_) => unreachable!("config validation should have failed!"),
        }
    }

    #[test]
    fn validate_dynamic_source() {
        let yaml = "
# Valid management address list.
version: v1alpha1
dynamic:
  management_servers:
    - address: 127.0.0.1:25999
    - address: example.com
    - address: http://127.0.0.1:30000
  ";
        let _ = validate_unwrap_ok(yaml);

        let yaml = "
# Invalid management address.
version: v1alpha1
dynamic:
  management_servers:
    - address: 'not an endpoint address'
  ";
        match validate_unwrap_err(yaml) {
            ValidationError::ValueInvalid(args) => {
                assert_eq!(args.field, "dynamic.management_servers.address".to_string());
            }
            err => unreachable!("expected invalid value error: got {}", err),
        }

        let yaml = "
# Duplicate management addresses.
version: v1alpha1
dynamic:
  management_servers:
    - address: 127.0.0.1:25999
    - address: 127.0.0.1:25999
  ";
        assert_eq!(
            ValidationError::NotUnique("dynamic.management_servers.address".to_string())
                .to_string(),
            validate_unwrap_err(yaml).to_string()
        );
    }

    #[test]
    fn validate() {
        // client - valid
        let yaml = "
version: v1alpha1
static:
  endpoints:
    - address: 127.0.0.1:25999
    - address: 127.0.0.1:25998
";
        let _ = validate_unwrap_ok(yaml);

        let yaml = "
# Non unique addresses.
version: v1alpha1
static:
  endpoints:
    - address: 127.0.0.1:25999
    - address: 127.0.0.1:25999
";
        assert_eq!(
            ValidationError::NotUnique("static.endpoints.address".to_string()).to_string(),
            validate_unwrap_err(yaml).to_string()
        );

        let yaml = "
# Empty endpoints list
version: v1alpha1
static:
  endpoints: []
";
        assert_eq!(
            ValidationError::EmptyList("static.endpoints".to_string()).to_string(),
            validate_unwrap_err(yaml).to_string()
        );
    }
}
