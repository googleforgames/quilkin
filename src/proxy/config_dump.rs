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

use crate::endpoint::Endpoint;
use hyper::http::HeaderValue;
use hyper::{Body, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct ClusterDump {
    name: &'static str,
    endpoints: Vec<Endpoint>,
}

#[derive(Debug, Serialize)]
struct ConfigDump {
    clusters: Vec<ClusterDump>,
    filterchain: FilterChainDump,
}

#[derive(Debug, Serialize)]
struct FilterConfigDump {
    name: String,
    config: Arc<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct FilterChainDump {
    filters: Vec<FilterConfigDump>,
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
            *response.body_mut() = Body::from(format!("failed to create config dump: {err}"));
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
    let filters = {
        let filter_manager = filter_manager.read();
        // Clone the list of filter configs immediately so that we don't hold on
        // to the filter manager's lock while serializing.
        filter_manager
            .get_filter_chain()
            .get_configs()
            .map(|(name, config)| FilterConfigDump {
                name: name.into(),
                config,
            })
            .collect::<Vec<_>>()
    };

    let dump = ConfigDump {
        clusters: vec![ClusterDump {
            name: "default-quilkin-cluster",
            endpoints,
        }],
        filterchain: FilterChainDump { filters },
    };

    serde_json::to_string_pretty(&dump)
}

#[cfg(test)]
mod tests {
    use super::handle_request;
    use crate::cluster::cluster_manager::ClusterManager;
    use crate::endpoint::{Endpoint, Endpoints};
    use crate::filters::{manager::FilterManager, CreateFilterArgs, FilterChain};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_handle_request() {
        let cluster_manager = ClusterManager::fixed(
            Endpoints::new(vec![Endpoint::new(([127, 0, 0, 1], 8080).into())]).unwrap(),
        )
        .unwrap();
        let debug_config = serde_yaml::from_str("id: hello").unwrap();

        let debug_factory = crate::filters::debug::factory();
        let debug_filter = debug_factory
            .create_filter(CreateFilterArgs::fixed(Some(debug_config)))
            .unwrap();
        let filter_manager = FilterManager::fixed(Arc::new(
            FilterChain::new(vec![(debug_factory.name().into(), debug_filter)]).unwrap(),
        ));

        let mut response = handle_request(cluster_manager, filter_manager);
        assert_eq!(response.status(), hyper::StatusCode::OK);
        assert_eq!(
            response.headers().get("Content-Type").unwrap(),
            "application/json"
        );
        let body = hyper::body::to_bytes(response.body_mut()).await.unwrap();
        let body = String::from_utf8(body.into_iter().collect()).unwrap();

        let expected = serde_json::json!({
            "clusters": [{
              "name": "default-quilkin-cluster",
              "endpoints": [{
                  "address": {
                      "host": "127.0.0.1",
                      "port": 8080,
                  },
                  "metadata": {
                      "quilkin.dev": {
                          "tokens": []
                      }
                  }
              }]
            }],
            "filterchain": {
                "filters": [{
                    "name": "quilkin.filters.debug.v1alpha1.Debug",
                    "config":{
                        "id": "hello"
                    }
                }]
            }
        });

        assert_eq!(
            expected,
            serde_json::from_str::<serde_json::Value>(body.as_str()).unwrap()
        );
    }
}
