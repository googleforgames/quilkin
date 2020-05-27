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
use crate::extensions::{Filter, FilterRegistry};

/// FilterChain implements a chain of Filters amd the implementation
/// of passing the information between Filters for each filter function
///
/// Each filter implementation loops around all the filters stored in the FilterChain, passing the results of each filter to the next in the chain.
/// The filter implementation returns the results of data that has gone through each of the filters in the chain.
/// If any of the Filters in the chain return a None, then the chain is broken, and nothing is returned.
pub struct FilterChain {
    filters: Vec<Arc<dyn Filter>>,
}

impl FilterChain {
    pub fn new(filters: Vec<Arc<dyn Filter>>) -> Self {
        FilterChain { filters }
    }

    // from_config returns a FilterChain from a given config. Will return a ErrorKind::InvalidInput
    // if there is an issue with the passed in Configuration.
    pub fn from_config(
        config: Arc<Config>,
        filter_registry: &FilterRegistry,
    ) -> Result<FilterChain> {
        let mut filters = Vec::<Arc<dyn Filter>>::new();
        for filter_config in &config.filters {
            match filter_registry.get(&filter_config.name) {
                None => {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        format!("Filter '{}' not found", filter_config.name),
                    ));
                }
                Some(filter) => {
                    filters.push(filter.clone());
                }
            }
        }
        Ok(FilterChain::new(filters))
    }
}

impl Filter for FilterChain {
    fn local_receive_filter(
        &self,
        endpoints: &Vec<EndPoint>,
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
        let mut e = endpoints.clone();
        let mut c = contents;
        for f in &self.filters {
            match f.local_receive_filter(&e, from, c) {
                None => return None,
                Some((endpoints, contents)) => {
                    e = endpoints;
                    c = contents;
                }
            }
        }
        Some((e, c))
    }

    fn local_send_filter(&self, to: SocketAddr, contents: Vec<u8>) -> Option<Vec<u8>> {
        let mut c = contents;
        for f in &self.filters {
            match f.local_send_filter(to, c) {
                None => return None,
                Some(contents) => {
                    c = contents;
                }
            }
        }
        Some(c)
    }

    fn endpoint_receive_filter(
        &self,
        endpoint: &EndPoint,
        recv_addr: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut c = contents;
        for f in &self.filters {
            match f.endpoint_receive_filter(&endpoint, recv_addr, c) {
                None => return None,
                Some(contents) => {
                    c = contents;
                }
            }
        }
        Some(c)
    }

    fn endpoint_send_filter(
        &self,
        endpoint: &EndPoint,
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut c = contents;
        for f in &self.filters {
            match f.endpoint_send_filter(&endpoint, from, c) {
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
    use crate::extensions::filters::DebugFilter;
    use crate::test_utils::logger;

    use super::*;
    use crate::extensions::default_filters;

    struct TestFilter {}

    impl Filter for TestFilter {
        fn local_receive_filter(
            &self,
            endpoints: &Vec<EndPoint>,
            from: SocketAddr,
            contents: Vec<u8>,
        ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
            let mut e = endpoints.clone();
            e.remove(0);

            let mut c = contents;
            c.append(&mut ":lcf:".as_bytes().to_vec());
            c.append(&mut from.to_string().as_bytes().to_vec());

            Some((e, c))
        }

        fn local_send_filter(&self, to: SocketAddr, contents: Vec<u8>) -> Option<Vec<u8>> {
            let mut c = contents;
            c.append(&mut ":lsf:".as_bytes().to_vec());
            c.append(&mut to.to_string().as_bytes().to_vec());
            Some(c)
        }

        fn endpoint_receive_filter(
            &self,
            endpoint: &EndPoint,
            recv_addr: SocketAddr,
            contents: Vec<u8>,
        ) -> Option<Vec<u8>> {
            let mut c = contents;
            c.append(&mut format!(":erf:{}:{}", endpoint.name, recv_addr).into_bytes());
            Some(c)
        }

        fn endpoint_send_filter(
            &self,
            endpoint: &EndPoint,
            from: SocketAddr,
            contents: Vec<u8>,
        ) -> Option<Vec<u8>> {
            let mut c = contents;
            c.append(&mut ":esf:".as_bytes().to_vec());

            let mut details = endpoint.name.clone();
            details.push_str(":");
            details.push_str(from.to_string().as_str());

            c.append(&mut details.as_bytes().to_vec());

            Some(c)
        }
    }

    #[test]
    fn from_config() {
        let log = logger();

        // everything is fine
        let config = Arc::new(Config {
            local: Local { port: 0 },
            filters: vec![config::Filter {
                name: DebugFilter::name(),
                config: Default::default(),
            }],
            connections: ConnectionConfig::Client {
                address: "127.0.0.1:2456".parse().unwrap(),
                connection_id: String::from(""),
            },
        });

        let registry = default_filters(&log);
        let chain = FilterChain::from_config(config, &registry).unwrap();
        assert_eq!(1, chain.filters.len());

        // uh oh, something went wrong
        let config = Arc::new(Config {
            local: Local { port: 0 },
            filters: vec![config::Filter {
                name: "this is so wrong".to_string(),
                config: Default::default(),
            }],
            connections: ConnectionConfig::Client {
                address: "127.0.0.1:2456".parse().unwrap(),
                connection_id: String::from(""),
            },
        });
        let result = FilterChain::from_config(config, &registry);
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
        let chain = FilterChain::new(vec![Arc::new(TestFilter {})]);

        let endpoints_fixture = endpoints();

        let (eps, content) = chain
            .local_receive_filter(
                &endpoints_fixture,
                "127.0.0.1:70".parse().unwrap(),
                "hello".as_bytes().to_vec(),
            )
            .unwrap();

        assert_eq!(vec![endpoints_fixture[1].clone()], eps);
        assert_eq!(
            "hello:lcf:127.0.0.1:70",
            from_utf8(content.as_slice()).unwrap()
        );

        let content = chain
            .local_send_filter("127.0.0.1:70".parse().unwrap(), "hello".as_bytes().to_vec())
            .unwrap();

        assert_eq!(
            "hello:lsf:127.0.0.1:70",
            from_utf8(content.as_slice()).unwrap()
        );

        let content = chain
            .endpoint_receive_filter(
                &endpoints_fixture[0],
                endpoints_fixture[0].address,
                "hello".as_bytes().to_vec(),
            )
            .unwrap();
        assert_eq!(
            "hello:erf:one:127.0.0.1:80",
            from_utf8(content.as_slice()).unwrap()
        );

        let content = chain
            .endpoint_send_filter(
                &endpoints_fixture[0],
                "127.0.0.1:60".parse().unwrap(),
                "hello".as_bytes().to_vec(),
            )
            .unwrap();

        assert_eq!(
            "hello:esf:one:127.0.0.1:60",
            from_utf8(content.as_slice()).unwrap()
        );
    }

    #[test]
    fn chain_double_test_filter() {
        let chain = FilterChain::new(vec![Arc::new(TestFilter {}), Arc::new(TestFilter {})]);

        let endpoints_fixture = endpoints();

        let (eps, content) = chain
            .local_receive_filter(
                &endpoints_fixture,
                "127.0.0.1:70".parse().unwrap(),
                "hello".as_bytes().to_vec(),
            )
            .unwrap();

        let empty: Vec<EndPoint> = Vec::new();
        assert_eq!(empty, eps);
        assert_eq!(
            "hello:lcf:127.0.0.1:70:lcf:127.0.0.1:70",
            from_utf8(content.as_slice()).unwrap()
        );

        let content = chain
            .local_send_filter("127.0.0.1:70".parse().unwrap(), "hello".as_bytes().to_vec())
            .unwrap();

        assert_eq!(
            "hello:lsf:127.0.0.1:70:lsf:127.0.0.1:70",
            from_utf8(content.as_slice()).unwrap()
        );

        let content = chain
            .endpoint_receive_filter(
                &endpoints_fixture[0],
                endpoints_fixture[0].address,
                "hello".as_bytes().to_vec(),
            )
            .unwrap();
        assert_eq!(
            "hello:erf:one:127.0.0.1:80:erf:one:127.0.0.1:80",
            from_utf8(content.as_slice()).unwrap()
        );

        let content = chain
            .endpoint_send_filter(
                &endpoints_fixture[0],
                "127.0.0.1:60".parse().unwrap(),
                "hello".as_bytes().to_vec(),
            )
            .unwrap();

        assert_eq!(
            "hello:esf:one:127.0.0.1:60:esf:one:127.0.0.1:60",
            from_utf8(content.as_slice()).unwrap()
        );
    }
}
