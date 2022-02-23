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

use std::sync::Arc;

use arc_swap::ArcSwap;
use prometheus::Result as MetricsResult;

use crate::{
    cluster::{metrics::Metrics, Cluster, ClusterMap},
    endpoint::{Endpoint, Endpoints, UpstreamEndpoints},
};

/// Knows about all clusters and endpoints.
#[derive(Clone)]
pub(crate) struct SharedCluster {
    metrics: Metrics,
    clusters: Arc<ArcSwap<ClusterMap>>,
}

impl SharedCluster {
    /// Returns a ClusterManager backed by the fixed set of clusters provided in the config.
    pub fn new(clusters: ClusterMap) -> MetricsResult<Self> {
        let metrics = Metrics::new()?;

        // Set the clusters count metrics.
        metrics
            .active_endpoints
            .set(clusters.endpoints().count() as i64);

        Ok(Self {
            metrics,
            clusters: Arc::new(ArcSwap::new(Arc::new(clusters))),
        })
    }

    /// Creates a new shared static cluster of `endpoints`.
    pub fn new_static_cluster(endpoints: Vec<Endpoint>) -> MetricsResult<Self> {
        const STATIC_CLUSTER_NAME: &str = "<static>";
        let cluster = Cluster::new_static_cluster(endpoints);
        let map = ClusterMap::from([(STATIC_CLUSTER_NAME.into(), cluster)]);

        Self::new(map)
    }

    /// Returns an empty [`SharedCluster`].
    pub fn empty() -> MetricsResult<Self> {
        Self::new(ClusterMap::default())
    }

    /// Provides a projection into the current cluster map.
    #[allow(unused)]
    pub fn load(&self) -> arc_swap::Guard<Arc<ClusterMap>> {
        self.clusters.load()
    }

    /// Updates the cluster to the `update`.
    pub fn store(&self, update: ClusterMap) {
        let num_clusters = update.len() as i64;
        let num_endpoints = update.endpoints().count() as i64;
        self.metrics.active_clusters.set(num_clusters);
        self.metrics.active_endpoints.set(num_endpoints);
        self.clusters.store(Arc::new(update));
    }

    /// Returns all endpoints known at the time of invocation.
    /// Returns `None` if there are no endpoints.
    pub fn endpoints(&self) -> Option<UpstreamEndpoints> {
        let endpoints: Vec<_> = self.clusters.load().endpoints().cloned().collect();

        (!endpoints.is_empty())
            .then(|| Endpoints::new(endpoints))
            .map(UpstreamEndpoints::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cluster::{Cluster, LocalityEndpoints},
        endpoint::{Endpoint, Metadata},
        metadata::MetadataView,
    };

    #[tokio::test]
    async fn dynamic_cluster_manager_process_cluster_update() {
        let shared_cluster = SharedCluster::empty().unwrap();

        fn mapping(entries: &[(&str, &str)]) -> serde_yaml::Mapping {
            entries
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect()
        }

        let test_endpoints = vec![
            Endpoint::with_metadata(
                "127.0.0.1:80".parse().unwrap(),
                MetadataView::with_unknown(
                    Metadata {
                        tokens: vec!["abc-0".into(), "xyz-0".into()].into_iter().collect(),
                    },
                    mapping(&[("key-01", "value-01"), ("key-02", "value-02")]),
                ),
            ),
            Endpoint::with_metadata(
                "127.0.0.1:82".parse().unwrap(),
                MetadataView::with_unknown(
                    Metadata {
                        tokens: vec!["abc-2".into(), "xyz-2".into()].into_iter().collect(),
                    },
                    mapping(&[("key-01", "value-01"), ("key-02", "value-02")]),
                ),
            ),
            Endpoint::with_metadata(
                "127.0.0.1:83".parse().unwrap(),
                Metadata {
                    tokens: vec!["abc-3".into(), "xyz-3".into()].into_iter().collect(),
                },
            ),
        ];

        let update = vec![
            (
                "cluster-1".into(),
                Cluster {
                    localities: vec![(
                        None,
                        LocalityEndpoints {
                            endpoints: vec![test_endpoints[0].clone()],
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            ),
            (
                "cluster-2".into(),
                Cluster {
                    localities: vec![(
                        None,
                        LocalityEndpoints {
                            endpoints: vec![test_endpoints[1].clone(), test_endpoints[2].clone()],
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            ),
        ]
        .into_iter()
        .collect();
        shared_cluster.store(update);

        // Check the processed update.
        tokio::time::timeout(std::time::Duration::from_secs(3), async move {
            // Wait for the update to be processed. Here just poll until there's
            // a change we expect (or we will timeout from the enclosing future eventually.
            loop {
                if let Some(endpoints) = shared_cluster.endpoints() {
                    let mut endpoints = endpoints.iter().cloned().collect::<Vec<_>>();
                    endpoints.sort_by(|a, b| a.address.cmp(&b.address));
                    assert_eq!(endpoints, test_endpoints);
                    break;
                } else {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                };
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn static_cluster_manager_metrics() {
        let shared_cluster = SharedCluster::new_static_cluster(vec![
            Endpoint::new("127.0.0.1:80".parse().unwrap()),
            Endpoint::new("127.0.0.1:81".parse().unwrap()),
        ])
        .unwrap();
        let metrics = &shared_cluster.metrics;
        assert_eq!(2, metrics.active_endpoints.get());
        assert_eq!(0, metrics.active_clusters.get());
    }

    #[tokio::test]
    async fn dynamic_cluster_manager_metrics() {
        let shared_cluster = SharedCluster::empty().unwrap();

        // Initialization metrics
        {
            let metrics = &shared_cluster.metrics;
            assert_eq!(0, metrics.active_endpoints.get());
            assert_eq!(0, metrics.active_clusters.get());
        }

        let update = vec![
            (
                "cluster-1".into(),
                Cluster {
                    localities: vec![(
                        None,
                        LocalityEndpoints {
                            endpoints: vec![Endpoint::new("127.0.0.1:80".parse().unwrap())],
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            ),
            (
                "cluster-2".into(),
                Cluster {
                    localities: vec![(
                        None,
                        LocalityEndpoints {
                            endpoints: vec![
                                Endpoint::new("127.0.0.1:82".parse().unwrap()),
                                Endpoint::new("127.0.0.1:83".parse().unwrap()),
                            ],
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            ),
        ]
        .into_iter()
        .collect();
        shared_cluster.store(update);

        // Check updated metrics
        tokio::time::timeout(std::time::Duration::from_secs(3), async move {
            // Wait for the update to be processed. Here just poll until there's
            // a change we expect (or we will timeout from the enclosing future eventually.
            loop {
                {
                    let metrics = &shared_cluster.metrics;
                    if metrics.active_endpoints.get() == 3 {
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(3)).await;
            }

            // Verify the new metrics are correct.
            {
                let metrics = &shared_cluster.metrics;
                assert_eq!(3, metrics.active_endpoints.get());
                assert_eq!(2, metrics.active_clusters.get());
            }
        })
        .await
        .unwrap();
    }
}
