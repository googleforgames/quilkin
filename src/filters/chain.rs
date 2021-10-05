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

use crate::capture_bytes::Context as CaptureBytesContext;
use crate::config::{
    CaptureVersion, Filter as FilterConfig, ValidationError,
    VersionedStaticFilterChain as VersionedStaticFilterChainConfig,
};
use crate::filters::{prelude::*, FilterRegistry};
use crate::metrics::CollectorExt;
use std::collections::HashMap;
use std::sync::Arc;

const FILTER_LABEL: &str = "filter";

/// A chain of [`Filter`]s to be executed in order.
///
/// Executes each filter, passing the [`ReadContext`] and [`WriteContext`]
/// between each filter's execution, returning the result of data that has gone
/// through all of the filters in the chain. If any of the filters in the chain
/// return `None`, then the chain is broken, and `None` is returned.
pub struct FilterChain {
    filters: Vec<(String, FilterInstance)>,
    filter_read_duration_seconds: Vec<Histogram>,
    filter_write_duration_seconds: Vec<Histogram>,
}

/// Filter chains can either be versioned of non versioned. So
/// this acts as a wrapper around a set of filter chains, providing
/// an API to retrieve them.
pub(crate) enum FilterChainSource {
    Versioned {
        capture_version: CaptureVersion,
        filter_chains: HashMap<Version, Arc<FilterChain>>,
    },
    NonVersioned(Arc<FilterChain>),
}

/// A filter chain version.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub(crate) struct Version(Vec<u8>);

impl From<Vec<u8>> for Version {
    fn from(value: Vec<u8>) -> Self {
        Version(value)
    }
}

impl AsRef<Vec<u8>> for Version {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

/// The return value of [`FilterChainSource::get_filter_chain`]
pub(crate) struct GetFilterChainResult {
    pub packet: Vec<u8>,
    pub version: Option<Version>,
    pub filter_chain: Arc<FilterChain>,
}

impl FilterChainSource {
    /// Creates a non-versioned filter chain from the provided config and
    /// returns an instance backed by that filter chain.
    pub fn non_versioned_from_config(
        filter_registry: &FilterRegistry,
        metrics_registry: &Registry,
        filter_configs: Vec<FilterConfig>,
    ) -> Result<Arc<FilterChainSource>, Error> {
        FilterChain::try_create(filter_configs, filter_registry, metrics_registry)
            .map(|filter_chain| Arc::new(FilterChainSource::NonVersioned(Arc::new(filter_chain))))
    }

    /// Creates a set of versioned filter chains from the provided config and
    /// returns an instance backed by the filter chains.
    pub fn versioned_from_config(
        filter_registry: &FilterRegistry,
        metrics_registry: &Registry,
        capture_version: CaptureVersion,
        filter_chains_config: Vec<VersionedStaticFilterChainConfig>,
    ) -> Result<Arc<FilterChainSource>, Error> {
        filter_chains_config
            .into_iter()
            .map(|config| {
                let filters = config.filters;
                let versions = config.versions;
                FilterChain::try_create(filters, filter_registry, metrics_registry)
                    .map(Arc::new)
                    .map(|filter_chain| {
                        versions
                            .into_iter()
                            .map(|version| (Version(version), filter_chain.clone()))
                            .collect::<Vec<_>>()
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|filter_chains| {
                Arc::new(FilterChainSource::Versioned {
                    capture_version,
                    filter_chains: filter_chains.into_iter().flatten().collect(),
                })
            })
    }

    /// Returns an instance backed by the provided non-versioned filter chain.
    pub fn non_versioned(filter_chain: FilterChain) -> Arc<FilterChainSource> {
        Arc::new(FilterChainSource::NonVersioned(Arc::new(filter_chain)))
    }

    /// Returns an instance backed by the provided set of versioned filter chains.
    pub fn versioned(
        capture_version: CaptureVersion,
        filter_chains: HashMap<Version, Arc<FilterChain>>,
    ) -> Arc<FilterChainSource> {
        Arc::new(FilterChainSource::Versioned {
            capture_version,
            filter_chains,
        })
    }

    /// Returns the capture version information if the proxy is configured to
    /// use versioned filter chains.
    pub fn get_capture_version(&self) -> Option<CaptureVersion> {
        match self {
            FilterChainSource::Versioned {
                capture_version,
                filter_chains: _,
            } => Some(capture_version.clone()),
            FilterChainSource::NonVersioned(_) => None,
        }
    }

    /// Returns the filter chain that matches the specified version.
    ///
    /// An error is returned if no match is found or the current instance
    /// is not backed by versioned filter chains.
    pub fn get_filter_chain_for_version(
        &self,
        version: &Version,
    ) -> Result<Arc<FilterChain>, GetFilterChainError> {
        match self {
            FilterChainSource::Versioned {
                filter_chains,
                capture_version: _,
            } => filter_chains
                .get(version)
                .cloned()
                .ok_or(GetFilterChainError::NoVersionMatch),
            FilterChainSource::NonVersioned(_) => Err(GetFilterChainError::NoVersionMatch),
        }
    }

    /// Returns the single non versioned filter chain only if this is a
    /// non versioned filter chain implementation.
    pub fn get_filter_chain_non_versioned(&self) -> Option<Arc<FilterChain>> {
        match self {
            FilterChainSource::NonVersioned(filter_chain) => Some(filter_chain.clone()),
            FilterChainSource::Versioned { .. } => None,
        }
    }

    /// Selects a filter chain for a packet - potentially capturing a version
    /// from the packet if configured to use a versioned filter chain.
    ///
    /// The potentially modified packet is returned back with the selected filter
    /// chain and any captured version.
    pub fn get_filter_chain(
        &self,
        packet: Vec<u8>,
    ) -> Result<GetFilterChainResult, GetFilterChainError> {
        match self {
            FilterChainSource::Versioned {
                capture_version,
                filter_chains: _,
            } => {
                // Capture the version from the packet.
                let capture_context = CaptureBytesContext {
                    strategy: capture_version.strategy.clone(),
                    size: capture_version.size,
                    remove: capture_version.remove,
                };

                let version_size = capture_version.size;
                let packet_size = packet.len();
                let processed_packet =
                    capture_context
                        .capture(packet)
                        .ok_or(GetFilterChainError::PacketTooSmall {
                            version_size,
                            packet_size,
                        })?;

                let packet = processed_packet.packet;
                let version = Version(processed_packet.captured_bytes);

                // Find a filter chain that matches the captured version.
                let filter_chain = self.get_filter_chain_for_version(&version)?;
                Ok(GetFilterChainResult {
                    packet,
                    version: Some(version),
                    filter_chain,
                })
            }
            FilterChainSource::NonVersioned(filter_chain) => Ok(GetFilterChainResult {
                packet,
                version: None,
                filter_chain: filter_chain.clone(),
            }),
        }
    }
}

/// Error returned when retrieving a filter chain.
#[derive(Debug, PartialEq, thiserror::Error)]
pub(crate) enum GetFilterChainError {
    #[error("the configured version size {version_size}Bytes is smaller larger than packet size {packet_size}Bytes")]
    PacketTooSmall {
        version_size: usize,
        packet_size: usize,
    },
    #[error("no filter matched the version captured from the packet")]
    NoVersionMatch,
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
    pub fn new(filters: Vec<(String, FilterInstance)>, registry: &Registry) -> Result<Self, Error> {
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

    /// Returns an iterator over the current filters' configs.
    pub(crate) fn get_configs(&self) -> impl Iterator<Item = (&str, Arc<serde_json::Value>)> {
        self.filters
            .iter()
            .map(|(config_json, config)| (config_json.as_str(), config.config.clone()))
    }
}

impl Filter for FilterChain {
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        self.filters
            .iter()
            .zip(self.filter_read_duration_seconds.iter())
            .try_fold(ctx, |ctx, ((_, instance), histogram)| {
                Some(ReadContext::with_response(
                    ctx.from,
                    histogram.observe_closure_duration(|| instance.filter.read(ctx))?,
                ))
            })
            .map(ReadResponse::from)
    }

    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        self.filters
            .iter()
            .rev()
            .zip(self.filter_write_duration_seconds.iter().rev())
            .try_fold(ctx, |ctx, ((_, instance), histogram)| {
                Some(WriteContext::with_response(
                    ctx.endpoint,
                    ctx.from,
                    ctx.to,
                    histogram.observe_closure_duration(|| instance.filter.write(ctx))?,
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
        test_utils::{logger, new_test_chain, TestFilterFactory},
    };

    use super::*;
    use crate::capture_bytes::Strategy;
    use crate::test_utils::{append_bytes_filter, new_registry};

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
                (
                    "TestFilter".into(),
                    TestFilterFactory::create_empty_filter(),
                ),
                (
                    "TestFilter".into(),
                    TestFilterFactory::create_empty_filter(),
                ),
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

    #[test]
    fn get_configs() {
        struct TestFilter2 {}
        impl Filter for TestFilter2 {}

        let registry = prometheus::Registry::default();
        let filter_chain = FilterChain::new(
            vec![
                (
                    "TestFilter".into(),
                    TestFilterFactory::create_empty_filter(),
                ),
                (
                    "TestFilter2".into(),
                    FilterInstance {
                        config: Arc::new(serde_json::json!({
                            "k1": "v1",
                            "k2": 2
                        })),
                        filter: Box::new(TestFilter2 {}),
                    },
                ),
            ],
            &registry,
        )
        .unwrap();

        let configs = filter_chain.get_configs().collect::<Vec<_>>();
        assert_eq!(
            vec![
                ("TestFilter", Arc::new(serde_json::Value::Null)),
                (
                    "TestFilter2",
                    Arc::new(serde_json::json!({
                        "k1": "v1",
                        "k2": 2
                    }))
                )
            ],
            configs
        )
    }

    #[test]
    fn get_versioned_filter_chain() {
        // Test that we can capture the version from packets and match
        // it to a filter chain.

        let filter_registry = new_registry(&logger());
        let filter_chain_source = FilterChainSource::versioned_from_config(
            &filter_registry,
            &prometheus::Registry::default(),
            CaptureVersion {
                strategy: Strategy::Prefix,
                size: 1,
                remove: true,
            },
            vec![
                VersionedStaticFilterChainConfig {
                    versions: vec![vec![0], vec![1]].into_iter().collect(),
                    filters: vec![append_bytes_filter("filter-0")],
                },
                VersionedStaticFilterChainConfig {
                    versions: vec![vec![2]].into_iter().collect(),
                    filters: vec![append_bytes_filter("filter-1")],
                },
            ],
        )
        .unwrap();

        let tests = vec![
            // (packet_version, expected_filter_chain)
            (vec![0], "filter-0"),
            (vec![1], "filter-0"),
            (vec![2], "filter-1"),
        ];

        let endpoints_fixture = endpoints();
        for (version, expected) in tests {
            let packet = vec![version.clone(), String::from("hello-").into_bytes()].concat();
            let got = filter_chain_source.get_filter_chain(packet).unwrap();
            let response = got
                .filter_chain
                .read(ReadContext::new(
                    upstream_endpoints(endpoints_fixture.clone()),
                    "127.0.0.1:70".parse().unwrap(),
                    got.packet,
                ))
                .unwrap();

            // Check that the version we extracted is what we expect.
            assert_eq!(version, got.version.unwrap().0);

            // Check the filter chain that got selected.
            assert_eq!(
                format!("hello-{}", expected),
                from_utf8(response.contents.as_slice()).unwrap()
            );
        }

        // No filter chain matches this version.
        let packet = vec![vec![3], String::from("hello-").into_bytes()].concat();
        assert_eq!(
            Some(GetFilterChainError::NoVersionMatch),
            filter_chain_source.get_filter_chain(packet).err()
        )
    }

    #[test]
    fn get_versioned_filter_chain_packet_too_small() {
        // Test that we get an error if a packet is too small to contain a version.
        let tests = vec![
            (Strategy::Prefix, true),
            (Strategy::Prefix, false),
            (Strategy::Suffix, true),
            (Strategy::Suffix, false),
        ];

        for (strategy, remove) in tests {
            let filter_registry = new_registry(&logger());
            let filter_chain_source = FilterChainSource::versioned_from_config(
                &filter_registry,
                &prometheus::Registry::default(),
                CaptureVersion {
                    strategy,
                    size: 10,
                    remove,
                },
                vec![VersionedStaticFilterChainConfig {
                    versions: vec![vec![0]].into_iter().collect(),
                    filters: vec![append_bytes_filter("filter-0")],
                }],
            )
            .unwrap();
            let packet = vec![vec![0], String::from("hello-").into_bytes()].concat();

            assert_eq!(
                Some(GetFilterChainError::PacketTooSmall {
                    version_size: 10,
                    packet_size: 7,
                }),
                filter_chain_source.get_filter_chain(packet).err()
            );
        }
    }

    #[test]
    fn get_versioned_filter_chain_different_capture_versions() {
        let metrics_registry = prometheus::Registry::default();
        let endpoints_fixture = endpoints();

        let tests = vec![
            // (packet_version, capture_strategy, capture_remove, expected_packet)
            (vec![104], Strategy::Prefix, true, "ello"),
            (vec![104], Strategy::Prefix, false, "hello"),
            (vec![108], Strategy::Suffix, true, "helo"),
            (vec![108], Strategy::Suffix, false, "hello"),
        ];

        for (version, strategy, remove, expected) in tests {
            let filter_registry = new_registry(&logger());
            let filter_chain_source = FilterChainSource::versioned_from_config(
                &filter_registry,
                &metrics_registry,
                CaptureVersion {
                    strategy,
                    size: 1,
                    remove,
                },
                vec![VersionedStaticFilterChainConfig {
                    versions: vec![version.clone()].into_iter().collect(),
                    filters: vec![append_bytes_filter("o")],
                }],
            )
            .unwrap();

            let packet = String::from("hell").into_bytes();
            let got = filter_chain_source.get_filter_chain(packet).unwrap();

            let response = got
                .filter_chain
                .read(ReadContext::new(
                    upstream_endpoints(endpoints_fixture.clone()),
                    "127.0.0.1:70".parse().unwrap(),
                    got.packet,
                ))
                .unwrap();

            // Check that the version we extracted is what we expect.
            assert_eq!(version, got.version.unwrap().0);

            // Check if the version was removed from the packet when requested.
            assert_eq!(expected, from_utf8(response.contents.as_slice()).unwrap());
        }
    }

    #[test]
    fn empty_filter_chain() {
        // Test that an empty versioned filter chain returns error for packets,
        // while an empty non-versioned filter chain does not
        let metrics_registry = prometheus::Registry::default();

        let filter_registry = new_registry(&logger());
        let versioned_filter_chain_source = FilterChainSource::versioned_from_config(
            &filter_registry,
            &metrics_registry,
            CaptureVersion {
                strategy: Strategy::Prefix,
                size: 1,
                remove: false,
            },
            vec![],
        )
        .unwrap();
        let non_versioned_filter_chain_source =
            FilterChainSource::non_versioned(FilterChain::new(vec![], &metrics_registry).unwrap());

        let packet = String::from("hello").into_bytes();
        assert_eq!(
            Some(GetFilterChainError::NoVersionMatch),
            versioned_filter_chain_source
                .get_filter_chain(packet.clone())
                .err()
        );
        assert!(non_versioned_filter_chain_source
            .get_filter_chain(packet)
            .is_ok());
    }
}
