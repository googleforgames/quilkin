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

use hyper::http::HeaderValue;
use hyper::{Body, Response, StatusCode};
use serde::Serialize;
use std::sync::Arc;

use crate::{cluster::SharedCluster, endpoint::Endpoint, filters::SharedFilterChain};

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
    cluster: SharedCluster,
    filter_chain: SharedFilterChain,
) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    match create_config_dump_json(cluster, filter_chain) {
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
    cluster: SharedCluster,
    filter_chain: SharedFilterChain,
) -> Result<String, serde_json::Error> {
    let endpoints = cluster
        .endpoints()
        .map(|upstream_endpoints| upstream_endpoints.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let filters = filter_chain
        .load()
        .get_configs()
        .map(|(name, config)| FilterConfigDump {
            name: name.into(),
            config,
        })
        .collect::<Vec<_>>();

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
    use crate::{
        cluster::{ClusterMap, SharedCluster},
        endpoint::Endpoint,
        filters::SharedFilterChain,
    };

    #[tokio::test]
    async fn test_handle_request() {
        let cluster = SharedCluster::new(ClusterMap::new_static(vec![Endpoint::new(
            ([127, 0, 0, 1], 8080).into(),
        )]))
        .unwrap();
        let filter_chain = SharedFilterChain::new(&[crate::config::Filter {
            name: crate::filters::debug::NAME.into(),
            config: Some(serde_yaml::from_str("id: hello").unwrap()),
        }])
        .unwrap();

        let mut response = handle_request(cluster, filter_chain);
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
