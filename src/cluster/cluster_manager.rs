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

// We use a parking_lot since it's significantly faster under low contention
// and we will need to acquire a read lock with every packet that is processed
// to be able to capture the current endpoint state and pass it to Filters.
use parking_lot::RwLock;

use prometheus::Result as MetricsResult;
use tokio::sync::{mpsc, watch};

use crate::endpoint::{Endpoints, UpstreamEndpoints};
use crate::xds::ads_client::ClusterUpdate;

use super::metrics::Metrics;

pub(crate) type SharedClusterManager = Arc<RwLock<ClusterManager>>;

/// ClusterManager knows about all clusters and endpoints.
pub(crate) struct ClusterManager {
    metrics: Metrics,
    endpoints: Option<Endpoints>,
}

/// InitializeError is returned with an error message if the
/// [`ClusterManager`] fails to initialize properly.
#[derive(Debug, thiserror::Error)]
pub enum InitializeError {
    #[error("{:?}", .0)]
    Message(String),
}

impl ClusterManager {
    fn new(endpoints: Option<Endpoints>) -> MetricsResult<Self> {
        let metrics = Metrics::new()?;
        Ok(Self { metrics, endpoints })
    }

    fn update(&mut self, endpoints: Option<Endpoints>) {
        self.endpoints = endpoints;
    }

    /// Returns all endpoints known at the time of invocation.
    /// Returns `None` if there are no endpoints.
    pub fn get_all_endpoints(&self) -> Option<UpstreamEndpoints> {
        self.endpoints.clone().map(|ep| ep.into())
    }

    /// Returns a ClusterManager backed by the fixed set of clusters provided in the config.
    pub fn fixed(endpoints: Endpoints) -> MetricsResult<SharedClusterManager> {
        let cm = Self::new(Some(endpoints))?;
        // Set the endpoints count metrics.
        cm.metrics.active_endpoints.set(
            cm.endpoints
                .as_ref()
                .map(|ep| ep.as_ref().len())
                .unwrap_or_default() as i64,
        );
        Ok(Arc::new(RwLock::new(cm)))
    }

    /// Returns a ClusterManager where the set of clusters is continuously
    /// updated based on responses from the provided updates channel.
    pub fn dynamic(
        cluster_updates_rx: mpsc::Receiver<ClusterUpdate>,
        shutdown_rx: watch::Receiver<()>,
    ) -> MetricsResult<SharedClusterManager> {
        let cluster_manager = Self::new(None)?;
        let metrics = cluster_manager.metrics.clone();
        let cluster_manager = Arc::new(RwLock::new(cluster_manager));

        // Start a task in the background to receive cluster updates
        // and update the cluster manager's cluster set in turn.
        Self::spawn_updater(
            metrics,
            cluster_manager.clone(),
            cluster_updates_rx,
            shutdown_rx,
        );

        Ok(cluster_manager)
    }

    fn process_cluster_update(metrics: &Metrics, update: ClusterUpdate) -> Option<Endpoints> {
        let num_clusters = update.len() as i64;
        let update = Self::create_endpoints_from_update(update);
        let num_endpoints = update
            .as_ref()
            .map(|ep| ep.as_ref().len() as i64)
            .unwrap_or_default();
        Self::update_cluster_update_metrics(metrics, num_clusters, num_endpoints);
        update
    }

    fn update_cluster_update_metrics(metrics: &Metrics, num_clusters: i64, num_endpoints: i64) {
        metrics.active_clusters.set(num_clusters);
        metrics.active_endpoints.set(num_endpoints)
    }

    fn create_endpoints_from_update(update: ClusterUpdate) -> Option<Endpoints> {
        // NOTE: We don't currently have support for consuming multiple clusters
        // so here gather all endpoints into the same set, ignoring what cluster they
        // belong to.
        let endpoints = update
            .into_iter()
            .fold(vec![], |mut endpoints, (_name, cluster)| {
                let cluster_endpoints = cluster
                    .localities
                    .into_iter()
                    .flat_map(|(_, endpoints)| endpoints.endpoints.into_iter());
                endpoints.extend(cluster_endpoints);

                endpoints
            });

        Endpoints::new(endpoints)
    }

    /// Spawns a task to run a loop that receives cluster updates
    /// and updates the ClusterManager's state in turn.
    fn spawn_updater(
        metrics: Metrics,
        cluster_manager: Arc<RwLock<ClusterManager>>,
        mut cluster_updates_rx: mpsc::Receiver<ClusterUpdate>,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    update = cluster_updates_rx.recv() => {
                        match update {
                            Some(update) => {
                                tracing::debug!("Received a cluster update.");
                                cluster_manager.write().update(Self::process_cluster_update(&metrics, update));
                            }
                            None => {
                                tracing::warn!("Exiting cluster update receive loop because the sender dropped the channel.");
                                return;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Exiting cluster update receive loop because a shutdown signal was received.");
                        return;
                    },
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::{mpsc, watch};

    use super::ClusterManager;
    use crate::{
        cluster::{Cluster, LocalityEndpoints},
        endpoint::{Endpoint, Endpoints, Metadata},
        metadata::MetadataView,
    };

    #[tokio::test]
    async fn dynamic_cluster_manager_process_cluster_update() {
        let (update_tx, update_rx) = mpsc::channel(3);
        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let cm = ClusterManager::dynamic(update_rx, shutdown_rx).unwrap();

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
        update_tx.send(update).await.unwrap();

        // Check the processed update.
        tokio::time::timeout(std::time::Duration::from_secs(3), async move {
            // Wait for the update to be processed. Here just poll until there's
            // a change we expect (or we will timeout from the enclosing future eventually.
            loop {
                let endpoints = { cm.read().endpoints.clone() };
                if let Some(endpoints) = endpoints {
                    let mut endpoints = endpoints.as_ref().clone();
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
        let cm = ClusterManager::fixed(
            Endpoints::new(vec![
                Endpoint::new("127.0.0.1:80".parse().unwrap()),
                Endpoint::new("127.0.0.1:81".parse().unwrap()),
            ])
            .unwrap(),
        )
        .unwrap();
        let metrics = &cm.read().metrics;
        assert_eq!(2, metrics.active_endpoints.get());
        assert_eq!(0, metrics.active_clusters.get());
    }

    #[tokio::test]
    async fn dynamic_cluster_manager_metrics() {
        let (update_tx, update_rx) = mpsc::channel(3);
        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let cm = ClusterManager::dynamic(update_rx, shutdown_rx).unwrap();

        // Initialization metrics
        {
            let metrics = &cm.read().metrics;
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
        update_tx.send(update).await.unwrap();

        // Check updated metrics
        tokio::time::timeout(std::time::Duration::from_secs(3), async move {
            // Wait for the update to be processed. Here just poll until there's
            // a change we expect (or we will timeout from the enclosing future eventually.
            loop {
                {
                    let metrics = &cm.read().metrics;
                    if metrics.active_endpoints.get() == 3 {
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(3)).await;
            }

            // Verify the new metrics are correct.
            {
                let metrics = &cm.read().metrics;
                assert_eq!(3, metrics.active_endpoints.get());
                assert_eq!(2, metrics.active_clusters.get());
            }
        })
        .await
        .unwrap();
    }
}
