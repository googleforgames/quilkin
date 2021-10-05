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

use crate::cluster::cluster_manager::SharedClusterManager;
use crate::filters::manager::SharedFilterManager;

use crate::config::CaptureVersion;
use crate::endpoint::{base64_set, Endpoint};
use crate::filters::{FilterChain, FilterChainSource};
use hyper::http::HeaderValue;
use hyper::{Body, Response, StatusCode};
use serde::Serialize;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct ClusterDump {
    name: &'static str,
    endpoints: Vec<Endpoint>,
}

#[derive(Debug, Serialize)]
struct ConfigDump {
    clusters: Vec<ClusterDump>,
    filter_chain: FilterChainsDump,
}

#[derive(Debug, Serialize)]
struct FilterConfigDump {
    name: String,
    config: Arc<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct FilterChainDump(Vec<FilterConfigDump>);

impl From<&Arc<FilterChain>> for FilterChainDump {
    fn from(filter_chain: &Arc<FilterChain>) -> Self {
        FilterChainDump(
            filter_chain
                .get_configs()
                .map(|(name, config)| FilterConfigDump {
                    name: name.into(),
                    config,
                })
                .collect(),
        )
    }
}

#[derive(Debug, Serialize)]
struct VersionedFilterChainDump {
    #[serde(with = "base64_set")]
    versions: base64_set::Set,
    filters: FilterChainDump,
}

#[derive(Debug, Serialize)]
enum FilterChainsDump {
    #[serde(rename = "versioned")]
    Versioned {
        capture_version: CaptureVersion,
        filter_chains: Vec<VersionedFilterChainDump>,
    },
    #[serde(rename = "filters")]
    NonVersioned(FilterChainDump),
}

pub(crate) fn handle_request(
    cluster_manager: SharedClusterManager,
    filter_manager: SharedFilterManager,
) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    match create_config_dump_json(cluster_manager, filter_manager) {
        Ok(body) => {
            *response.status_mut() = StatusCode::OK;
            response
                .headers_mut()
                .insert("Content-Type", HeaderValue::from_static("application/json"));
            *response.body_mut() = Body::from(body);
        }
        Err(err) => {
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            *response.body_mut() = Body::from(format!("failed to create config dump: {}", err));
        }
    }

    response
}

fn create_config_dump_json(
    cluster_manager: SharedClusterManager,
    filter_manager: SharedFilterManager,
) -> Result<String, serde_json::Error> {
    let endpoints = {
        let cluster_manager = cluster_manager.read();
        // Clone the list of endpoints immediately so that we don't hold on
        // to the cluster manager's lock while serializing.
        cluster_manager
            .get_all_endpoints()
            .map(|upstream_endpoints| upstream_endpoints.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };

    let filter_chains = {
        let filter_manager = filter_manager.read();
        // Clone the list of filter configs immediately so that we don't hold on
        // to the filter manager's lock while serializing.
        let filter_chain_source = filter_manager.get_filter_chain_source();
        match filter_chain_source {
            FilterChainSource::Versioned {
                capture_version,
                filter_chains,
            } => {
                let grouped_by_chain = filter_chains.iter().fold(
                    HashMap::new(),
                    |mut acc: HashMap<*const _, VersionedFilterChainDump>,
                     (version, filter_chain)| {
                        match acc.entry(Arc::as_ptr(filter_chain)) {
                            Entry::Vacant(entry) => {
                                entry.insert(VersionedFilterChainDump {
                                    versions: Some(version.as_ref().clone()).into_iter().collect(),
                                    filters: filter_chain.into(),
                                });
                            }
                            Entry::Occupied(mut entry) => {
                                let dump = &mut entry.get_mut();
                                dump.versions.insert(version.as_ref().clone());
                            }
                        };

                        acc
                    },
                );

                let capture_version = capture_version.clone();
                // No need to hold on to the lock after we've copied the data we want.
                drop(filter_manager);

                let mut filter_chains = grouped_by_chain.into_values().collect::<Vec<_>>();
                // Sort the list of versioned filters by their versions list so that we
                // get a consistent ordering in the output.
                // Versions are unique across filter chains so we can use an unstable sort.
                filter_chains.sort_unstable_by(|a, b| a.versions.cmp(&b.versions));
                FilterChainsDump::Versioned {
                    capture_version,
                    filter_chains,
                }
            }
            FilterChainSource::NonVersioned(filter_chain) => {
                FilterChainsDump::NonVersioned(filter_chain.into())
            }
        }
    };

    let dump = ConfigDump {
        clusters: vec![ClusterDump {
            name: "default-quilkin-cluster",
            endpoints,
        }],
        filter_chain: filter_chains,
    };

    serde_json::to_string_pretty(&dump)
}

#[cfg(test)]
mod tests {
    use super::handle_request;
    use crate::capture_bytes::Strategy;
    use crate::cluster::cluster_manager::ClusterManager;
    use crate::config::CaptureVersion;
    use crate::endpoint::{Endpoint, Endpoints};
    use crate::filters::manager::FilterManager;
    use crate::filters::{CreateFilterArgs, FilterChain, FilterChainSource, FilterInstance};
    use crate::test_utils::logger;
    use prometheus::Registry;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_handle_request() {
        let registry = Registry::default();

        fn debug_filter(value: &'static str) -> (String, FilterInstance) {
            let debug_factory = crate::filters::debug::factory(&logger());
            (
                debug_factory.name().into(),
                debug_factory
                    .create_filter(CreateFilterArgs::fixed(
                        Registry::default(),
                        Some(
                            &serde_yaml::from_str(
                                format!(
                                    "
id: {}
",
                                    value
                                )
                                .as_str(),
                            )
                            .unwrap(),
                        ),
                    ))
                    .unwrap(),
            )
        }

        let tests = vec![
            {
                (
                    FilterManager::fixed(FilterChainSource::non_versioned(
                        FilterChain::new(vec![debug_filter("hello")], &registry).unwrap(),
                    )),
                    serde_json::json!({
                        "clusters": [{
                          "name": "default-quilkin-cluster",
                          "endpoints": [{
                              "address": "127.0.0.1:8080",
                              "metadata": {
                                  "quilkin.dev": {
                                      "tokens": []
                                  }
                              }
                          }]
                        }],
                        "filter_chain": {
                            "filters": [{
                                "name": "quilkin.extensions.filters.debug.v1alpha1.Debug",
                                "config":{
                                    "id": "hello"
                                }
                            }]
                        }
                    }),
                )
            },
            {
                (
                    FilterManager::fixed(FilterChainSource::versioned(
                        CaptureVersion {
                            strategy: Strategy::Suffix,
                            size: 3,
                            remove: true,
                        },
                        {
                            let chain1 = Arc::new(
                                FilterChain::new(vec![debug_filter("hello-1")], &registry).unwrap(),
                            );
                            let chain2 = Arc::new(
                                FilterChain::new(vec![debug_filter("hello-2")], &registry).unwrap(),
                            );
                            vec![
                                (vec![0].into(), chain1.clone()),
                                (vec![1].into(), chain1),
                                (vec![2].into(), chain2),
                            ]
                            .into_iter()
                            .collect()
                        },
                    )),
                    serde_json::json!({
                        "clusters": [{
                          "name": "default-quilkin-cluster",
                          "endpoints": [{
                              "address": "127.0.0.1:8080",
                              "metadata": {
                                  "quilkin.dev": {
                                      "tokens": []
                                  }
                              }
                          }]
                        }],
                        "filter_chain": {
                            "versioned": {
                                "capture_version": {
                                    "strategy": "SUFFIX",
                                    "size": 3,
                                    "remove": true
                                },
                                "filter_chains": [
                                    {
                                        "versions": [ "AA==", "AQ==" ],
                                        "filters": [{
                                            "name": "quilkin.extensions.filters.debug.v1alpha1.Debug",
                                            "config":{
                                                "id": "hello-1"
                                            }
                                        }]
                                    },
                                    {
                                        "versions": [ "Ag==" ],
                                        "filters": [{
                                            "name": "quilkin.extensions.filters.debug.v1alpha1.Debug",
                                            "config":{
                                                "id": "hello-2"
                                            }
                                        }]
                                    }
                                ]
                            }
                        }
                    }),
                )
            },
        ];

        for (filter_manager, expected) in tests {
            let cluster_manager = ClusterManager::fixed(
                &registry,
                Endpoints::new(vec![Endpoint::new("127.0.0.1:8080".parse().unwrap())]).unwrap(),
            )
            .unwrap();
            let mut response = handle_request(cluster_manager, filter_manager);
            assert_eq!(response.status(), hyper::StatusCode::OK);
            assert_eq!(
                response.headers().get("Content-Type").unwrap(),
                "application/json"
            );
            let body = hyper::body::to_bytes(response.body_mut()).await.unwrap();
            let body = String::from_utf8(body.into_iter().collect()).unwrap();
            assert_eq!(
                expected,
                serde_json::from_str::<serde_json::Value>(body.as_str()).unwrap()
            );
        }
    }
}
