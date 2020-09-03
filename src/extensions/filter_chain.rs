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

use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::{Config, EndPoint};
use crate::extensions::{CreateFilterArgs, Filter, FilterRegistry};
use prometheus::Registry;

/// FilterChain implements a chain of Filters amd the implementation
/// of passing the information between Filters for each filter function
///
/// Each filter implementation loops around all the filters stored in the FilterChain, passing the results of each filter to the next in the chain.
/// The filter implementation returns the results of data that has gone through each of the filters in the chain.
/// If any of the Filters in the chain return a None, then the chain is broken, and nothing is returned.
pub struct FilterChain {
    filters: Vec<Box<dyn Filter>>,
}

impl FilterChain {
    pub fn new(filters: Vec<Box<dyn Filter>>) -> Self {
        FilterChain { filters }
    }

    // from_arguments returns a FilterChain from the provided arguments.
    // Will return a ErrorKind::InvalidInput if there is an issue with the passed
    // in Configuration.
    pub fn from_arguments(
        config: Arc<Config>,
        filter_registry: &FilterRegistry,
        metrics_registry: &Registry,
    ) -> Result<FilterChain> {
        let mut filters = Vec::<Box<dyn Filter>>::new();
        for filter_config in &config.filters {
            match filter_registry.get(
                &filter_config.name,
                CreateFilterArgs::new(&config.connections, filter_config.config.as_ref())
                    .with_metrics_registry(metrics_registry.clone()),
            ) {
                Ok(filter) => filters.push(filter),
                Err(err) => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Issue with filter '{}': {}", filter_config.name, err),
                    ));
                }
            }
        }
        Ok(FilterChain::new(filters))
    }
}

impl Filter for FilterChain {
    fn on_downstream_receive(
        &self,
        endpoints: &[EndPoint],
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
        let mut e = endpoints.to_vec();
        let mut c = contents;
        for f in &self.filters {
            match f.on_downstream_receive(&e, from, c) {
                None => return None,
                Some((endpoints, contents)) => {
                    e = endpoints;
                    c = contents;
                }
            }
        }
        Some((e, c))
    }

    fn on_upstream_receive(
        &self,
        endpoint: &EndPoint,
        from: SocketAddr,
        to: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut c = contents;
        for f in &self.filters {
            match f.on_upstream_receive(&endpoint, from, to, c) {
                None => return None,
                Some(contents) => {
                    c = contents;
                }
            }
        }
        Some(c)
    }
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;

    use crate::config;
    use crate::config::{ConnectionConfig, Local};
    use crate::extensions::filters::DebugFilterFactory;
    use crate::extensions::{default_registry, FilterFactory};
    use crate::test_utils::{logger, noop_endpoint, TestFilter};

    use super::*;

    #[test]
    fn from_config() {
        let log = logger();
        let provider = DebugFilterFactory::new(&log);

        // everything is fine
        let config = Arc::new(Config {
            local: Local { port: 0 },
            filters: vec![config::Filter {
                name: provider.name(),
                config: Default::default(),
            }],
            connections: ConnectionConfig::Client {
                addresses: vec!["127.0.0.1:2456".parse().unwrap()],
                connection_id: "".into(),
                lb_policy: None,
            },
        });

        let registry = default_registry(&log);
        let chain = FilterChain::from_arguments(config, &registry, &Registry::default()).unwrap();
        assert_eq!(1, chain.filters.len());

        // uh oh, something went wrong
        let config = Arc::new(Config {
            local: Local { port: 0 },
            filters: vec![config::Filter {
                name: "this is so wrong".to_string(),
                config: Default::default(),
            }],
            connections: ConnectionConfig::Client {
                addresses: vec!["127.0.0.1:2456".parse().unwrap()],
                connection_id: "".into(),
                lb_policy: None,
            },
        });
        let result = FilterChain::from_arguments(config, &registry, &Registry::default());
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

        let (eps, content) = chain
            .on_downstream_receive(
                &endpoints_fixture,
                "127.0.0.1:70".parse().unwrap(),
                "hello".as_bytes().to_vec(),
            )
            .unwrap();

        let mut expected = endpoints_fixture.clone();
        expected.push(noop_endpoint());
        assert_eq!(expected, eps);
        assert_eq!(
            "hello:odr:127.0.0.1:70",
            from_utf8(content.as_slice()).unwrap()
        );

        let content = chain
            .on_upstream_receive(
                &endpoints_fixture[0],
                endpoints_fixture[0].address,
                "127.0.0.1:70".parse().unwrap(),
                "hello".as_bytes().to_vec(),
            )
            .unwrap();
        assert_eq!(
            "hello:our:one:127.0.0.1:80:127.0.0.1:70",
            from_utf8(content.as_slice()).unwrap()
        );
    }

    #[test]
    fn chain_double_test_filter() {
        let chain = FilterChain::new(vec![Box::new(TestFilter {}), Box::new(TestFilter {})]);

        let endpoints_fixture = endpoints();

        let (eps, content) = chain
            .on_downstream_receive(
                &endpoints_fixture,
                "127.0.0.1:70".parse().unwrap(),
                "hello".as_bytes().to_vec(),
            )
            .unwrap();

        let mut expected = endpoints_fixture.clone();
        expected.push(noop_endpoint());
        expected.push(noop_endpoint());
        assert_eq!(expected, eps);
        assert_eq!(
            "hello:odr:127.0.0.1:70:odr:127.0.0.1:70",
            from_utf8(content.as_slice()).unwrap()
        );

        let content = chain
            .on_upstream_receive(
                &endpoints_fixture[0],
                endpoints_fixture[0].address,
                "127.0.0.1:70".parse().unwrap(),
                "hello".as_bytes().to_vec(),
            )
            .unwrap();
        assert_eq!(
            "hello:our:one:127.0.0.1:80:127.0.0.1:70:our:one:127.0.0.1:80:127.0.0.1:70",
            from_utf8(content.as_slice()).unwrap()
        );
    }
}
