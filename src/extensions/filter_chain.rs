/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use std::fmt::{self, Formatter};
use std::sync::Arc;

use prometheus::Registry;

use crate::config::{Config, ValidationError};
use crate::extensions::{
    CreateFilterArgs, DownstreamContext, DownstreamResponse, Filter, FilterRegistry,
    UpstreamContext, UpstreamResponse,
};

/// FilterChain implements a chain of Filters amd the implementation
/// of passing the information between Filters for each filter function
///
/// Each filter implementation loops around all the filters stored in the FilterChain, passing the results of each filter to the next in the chain.
/// The filter implementation returns the results of data that has gone through each of the filters in the chain.
/// If any of the Filters in the chain return a None, then the chain is broken, and nothing is returned.
pub struct FilterChain {
    filters: Vec<Box<dyn Filter>>,
}

/// Represents an error while creating a `FilterChain`
#[derive(Debug)]
pub struct CreateFilterError {
    filter_name: String,
    error: ValidationError,
}

impl fmt::Display for CreateFilterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to create filter {}: {}",
            self.filter_name,
            format!("{}", self.error)
        )
    }
}

impl FilterChain {
    pub fn new(filters: Vec<Box<dyn Filter>>) -> Self {
        FilterChain { filters }
    }

    /// Validates the filter configurations in the provided config and constructs
    /// a FilterChain if all configurations are valid.
    pub fn try_create(
        config: Arc<Config>,
        filter_registry: &FilterRegistry,
        metrics_registry: &Registry,
    ) -> std::result::Result<FilterChain, CreateFilterError> {
        let mut filters = Vec::<Box<dyn Filter>>::new();
        for filter_config in &config.filters {
            match filter_registry.get(
                &filter_config.name,
                CreateFilterArgs::new(&config.connections, filter_config.config.as_ref())
                    .with_metrics_registry(metrics_registry.clone()),
            ) {
                Ok(filter) => filters.push(filter),
                Err(err) => {
                    return Err(CreateFilterError {
                        filter_name: filter_config.name.clone(),
                        error: err.into(),
                    });
                }
            }
        }
        Ok(FilterChain::new(filters))
    }
}

impl Filter for FilterChain {
    fn on_downstream_receive(&self, mut ctx: DownstreamContext) -> Option<DownstreamResponse> {
        let from = ctx.from;
        for f in &self.filters {
            match f.on_downstream_receive(ctx) {
                None => return None,
                Some(response) => ctx = DownstreamContext::with_response(from, response),
            }
        }
        Some(ctx.into())
    }

    fn on_upstream_receive(&self, mut ctx: UpstreamContext) -> Option<UpstreamResponse> {
        let endpoint = ctx.endpoint;
        let from = ctx.from;
        let to = ctx.to;
        for f in &self.filters {
            match f.on_upstream_receive(ctx) {
                None => return None,
                Some(response) => {
                    ctx = UpstreamContext::with_response(endpoint, from, to, response);
                }
            }
        }
        Some(ctx.into())
    }
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;

    use crate::config;
    use crate::config::{Builder, ConnectionConfig, EndPoint};
    use crate::extensions::filters::DebugFactory;
    use crate::extensions::{default_registry, FilterFactory};
    use crate::test_utils::{logger, noop_endpoint, TestFilter};

    use super::*;

    #[test]
    fn from_config() {
        let log = logger();
        let provider = DebugFactory::new(&log);

        // everything is fine
        let config = Builder::empty()
            .with_filters(vec![config::Filter {
                name: provider.name(),
                config: Default::default(),
            }])
            .with_connections(ConnectionConfig::Client {
                addresses: vec!["127.0.0.1:2456".parse().unwrap()],
                connection_id: "".into(),
                lb_policy: None,
            })
            .build();

        let registry = default_registry(&log);
        let chain =
            FilterChain::try_create(Arc::new(config), &registry, &Registry::default()).unwrap();
        assert_eq!(1, chain.filters.len());

        // uh oh, something went wrong
        let config = Builder::empty()
            .with_filters(vec![config::Filter {
                name: "this is so wrong".to_string(),
                config: Default::default(),
            }])
            .with_connections(ConnectionConfig::Client {
                addresses: vec!["127.0.0.1:2456".parse().unwrap()],
                connection_id: "".into(),
                lb_policy: None,
            })
            .build();
        let result = FilterChain::try_create(Arc::new(config), &registry, &Registry::default());
        assert!(result.is_err());
    }

    fn endpoints() -> Vec<EndPoint> {
        vec![
            EndPoint {
                name: "one".to_string(),
                address: "127.0.0.1:80".parse().unwrap(),
                connection_ids: vec![],
            },
            EndPoint {
                name: "two".to_string(),
                address: "127.0.0.1:90".parse().unwrap(),
                connection_ids: vec![],
            },
        ]
    }

    #[test]
    fn chain_single_test_filter() {
        let chain = FilterChain::new(vec![Box::new(TestFilter {})]);

        let endpoints_fixture = endpoints();

        let response = chain
            .on_downstream_receive(DownstreamContext::new(
                endpoints_fixture.clone(),
                "127.0.0.1:70".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .unwrap();

        let mut expected = endpoints_fixture.clone();
        expected.push(noop_endpoint());
        assert_eq!(expected, response.endpoints);
        assert_eq!(
            "hello:odr:127.0.0.1:70",
            from_utf8(response.contents.as_slice()).unwrap()
        );
        assert_eq!(
            "receive",
            response.values["downstream"]
                .downcast_ref::<String>()
                .unwrap()
        );

        let response = chain
            .on_upstream_receive(UpstreamContext::new(
                &endpoints_fixture[0],
                endpoints_fixture[0].address,
                "127.0.0.1:70".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .unwrap();

        assert_eq!(
            "receive",
            response.values["upstream"]
                .downcast_ref::<String>()
                .unwrap()
        );
        assert_eq!(
            "hello:our:one:127.0.0.1:80:127.0.0.1:70",
            from_utf8(response.contents.as_slice()).unwrap()
        );
    }

    #[test]
    fn chain_double_test_filter() {
        let chain = FilterChain::new(vec![Box::new(TestFilter {}), Box::new(TestFilter {})]);

        let endpoints_fixture = endpoints();

        let response = chain
            .on_downstream_receive(DownstreamContext::new(
                endpoints_fixture.clone(),
                "127.0.0.1:70".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .unwrap();

        let mut expected = endpoints_fixture.clone();
        expected.push(noop_endpoint());
        expected.push(noop_endpoint());
        assert_eq!(expected, response.endpoints);
        assert_eq!(
            "hello:odr:127.0.0.1:70:odr:127.0.0.1:70",
            from_utf8(response.contents.as_slice()).unwrap()
        );
        assert_eq!(
            "receive:receive",
            response.values["downstream"]
                .downcast_ref::<String>()
                .unwrap()
        );

        let response = chain
            .on_upstream_receive(UpstreamContext::new(
                &endpoints_fixture[0],
                endpoints_fixture[0].address,
                "127.0.0.1:70".parse().unwrap(),
                b"hello".to_vec(),
            ))
            .unwrap();
        assert_eq!(
            "hello:our:one:127.0.0.1:80:127.0.0.1:70:our:one:127.0.0.1:80:127.0.0.1:70",
            from_utf8(response.contents.as_slice()).unwrap()
        );
        assert_eq!(
            "receive:receive",
            response.values["upstream"]
                .downcast_ref::<String>()
                .unwrap()
        );
    }
}
