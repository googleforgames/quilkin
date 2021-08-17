/*
 * Copyright 2020 Google LLC
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

use prometheus::{Error as PrometheusError, Histogram, HistogramOpts, Registry};

use crate::config::{Filter as FilterConfig, ValidationError};
use crate::filters::{prelude::*, FilterRegistry};
use crate::metrics::CollectorExt;

const FILTER_LABEL: &str = "filter";

/// A chain of [`Filter`]s to be executed in order.
///
/// Executes each filter, passing the [`ReadContext`] and [`WriteContext`]
/// between each filter's execution, returning the result of data that has gone
/// through all of the filters in the chain. If any of the filters in the chain
/// return `None`, then the chain is broken, and `None` is returned.
pub struct FilterChain {
    filters: Vec<(String, Box<dyn Filter>)>,
    filter_read_duration_seconds: Vec<Histogram>,
    filter_write_duration_seconds: Vec<Histogram>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{}", .0)]
    Prometheus(PrometheusError),
    #[error("failed to create filter {}: {}", filter_name, error)]
    Filter {
        filter_name: String,
        error: ValidationError,
    },
}

impl From<PrometheusError> for Error {
    fn from(error: PrometheusError) -> Self {
        Self::Prometheus(error)
    }
}

impl FilterChain {
    pub fn new(
        filters: Vec<(String, Box<dyn Filter>)>,
        registry: &Registry,
    ) -> Result<Self, Error> {
        Ok(Self {
            filter_read_duration_seconds: filters
                .iter()
                .map(|(name, _)| {
                    Histogram::with_opts(
                        HistogramOpts::new(
                            "filter_read_duration_seconds",
                            "Seconds taken to execute a given filter's `read`.",
                        )
                        .const_label(FILTER_LABEL, name),
                    )
                    .and_then(|histogram| histogram.register_if_not_exists(registry))
                })
                .collect::<Result<_, prometheus::Error>>()?,
            filter_write_duration_seconds: filters
                .iter()
                .map(|(name, _)| {
                    Histogram::with_opts(
                        HistogramOpts::new(
                            "filter_write_duration_seconds",
                            "Seconds taken to execute a given filter's `write`.",
                        )
                        .const_label(FILTER_LABEL, name),
                    )
                    .and_then(|histogram| histogram.register_if_not_exists(registry))
                })
                .collect::<Result<_, prometheus::Error>>()?,
            filters,
        })
    }

    /// Validates the filter configurations in the provided config and constructs
    /// a FilterChain if all configurations are valid.
    pub fn try_create(
        filter_configs: Vec<FilterConfig>,
        filter_registry: &FilterRegistry,
        metrics_registry: &Registry,
    ) -> Result<Self, Error> {
        let mut filters = Vec::new();

        for filter_config in filter_configs {
            match filter_registry.get(
                &filter_config.name,
                CreateFilterArgs::fixed(metrics_registry.clone(), filter_config.config.as_ref())
                    .with_metrics_registry(metrics_registry.clone()),
            ) {
                Ok(filter) => filters.push((filter_config.name, filter)),
                Err(err) => {
                    return Err(Error::Filter {
                        filter_name: filter_config.name.clone(),
                        error: err.into(),
                    });
                }
            }
        }

        FilterChain::new(filters, metrics_registry)
    }
}

impl Filter for FilterChain {
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        self.filters
            .iter()
            .zip(self.filter_read_duration_seconds.iter())
            .try_fold(ctx, |ctx, ((_, filter), histogram)| {
                Some(ReadContext::with_response(
                    ctx.from,
                    histogram.observe_closure_duration(|| filter.read(ctx))?,
                ))
            })
            .map(ReadResponse::from)
    }

    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        self.filters
            .iter()
            .rev()
            .zip(self.filter_write_duration_seconds.iter().rev())
            .try_fold(ctx, |ctx, ((_, filter), histogram)| {
                Some(WriteContext::with_response(
                    ctx.endpoint,
                    ctx.from,
                    ctx.to,
                    histogram.observe_closure_duration(|| filter.write(ctx))?,
                ))
            })
            .map(WriteResponse::from)
    }
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;

    use crate::{
        config,
        endpoint::{Endpoint, Endpoints, UpstreamEndpoints},
        filters::{debug, FilterRegistry, FilterSet},
        test_utils::{logger, new_test_chain, TestFilter},
    };

    use super::*;

    #[test]
    fn from_config() {
        let log = logger();
        let provider = debug::factory(&log);

        // everything is fine
        let filter_configs = vec![config::Filter {
            name: provider.name().into(),
            config: Default::default(),
        }];

        let registry = FilterRegistry::new(FilterSet::default(&log));
        let chain =
            FilterChain::try_create(filter_configs, &registry, &Registry::default()).unwrap();
        assert_eq!(1, chain.filters.len());

        // uh oh, something went wrong
        let filter_configs = vec![config::Filter {
            name: "this is so wrong".into(),
            config: Default::default(),
        }];
        let result = FilterChain::try_create(filter_configs, &registry, &Registry::default());
        assert!(result.is_err());
    }

    fn endpoints() -> Vec<Endpoint> {
        vec![
            Endpoint::new("127.0.0.1:80".parse().unwrap()),
            Endpoint::new("127.0.0.1:90".parse().unwrap()),
        ]
    }

    fn upstream_endpoints(endpoints: Vec<Endpoint>) -> UpstreamEndpoints {
        Endpoints::new(endpoints).unwrap().into()
    }

    #[test]
    fn chain_single_test_filter() {
        let registry = prometheus::Registry::default();
        let chain = new_test_chain(&registry);
        let endpoints_fixture = endpoints();

        let response = chain
            .read(ReadContext::new(
                upstream_endpoints(endpoints_fixture.clone()),
                "127.0.0.1:70".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .unwrap();

        let expected = endpoints_fixture.clone();
        assert_eq!(
            expected,
            response.endpoints.iter().cloned().collect::<Vec<_>>()
        );
        assert_eq!(
            "hello:odr:127.0.0.1:70",
            from_utf8(response.contents.as_slice()).unwrap()
        );
        assert_eq!(
            "receive",
            response.metadata[&"downstream".to_string()]
                .downcast_ref::<String>()
                .unwrap()
        );

        let response = chain
            .write(WriteContext::new(
                &endpoints_fixture[0],
                endpoints_fixture[0].address,
                "127.0.0.1:70".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .unwrap();

        assert_eq!(
            "receive",
            response.metadata["upstream"]
                .downcast_ref::<String>()
                .unwrap()
        );
        assert_eq!(
            "hello:our:127.0.0.1:80:127.0.0.1:70",
            from_utf8(response.contents.as_slice()).unwrap()
        );
    }

    #[test]
    fn chain_double_test_filter() {
        let registry = prometheus::Registry::default();
        let chain = FilterChain::new(
            vec![
                ("TestFilter".into(), Box::new(TestFilter {})),
                ("TestFilter".into(), Box::new(TestFilter {})),
            ],
            &registry,
        )
        .unwrap();

        let endpoints_fixture = endpoints();

        let response = chain
            .read(ReadContext::new(
                upstream_endpoints(endpoints_fixture.clone()),
                "127.0.0.1:70".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .unwrap();

        let expected = endpoints_fixture.clone();
        assert_eq!(
            expected,
            response.endpoints.iter().cloned().collect::<Vec<_>>()
        );
        assert_eq!(
            "hello:odr:127.0.0.1:70:odr:127.0.0.1:70",
            from_utf8(response.contents.as_slice()).unwrap()
        );
        assert_eq!(
            "receive:receive",
            response.metadata[&"downstream".to_string()]
                .downcast_ref::<String>()
                .unwrap()
        );

        let response = chain
            .write(WriteContext::new(
                &endpoints_fixture[0],
                endpoints_fixture[0].address,
                "127.0.0.1:70".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .unwrap();
        assert_eq!(
            "hello:our:127.0.0.1:80:127.0.0.1:70:our:127.0.0.1:80:127.0.0.1:70",
            from_utf8(response.contents.as_slice()).unwrap()
        );
        assert_eq!(
            "receive:receive",
            response.metadata["upstream"]
                .downcast_ref::<String>()
                .unwrap()
        );
    }
}
