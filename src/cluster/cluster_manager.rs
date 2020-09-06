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

use parking_lot::RwLock;
use slog::{info, warn, Logger};
use std::{fmt, sync::Arc};
use tokio::sync::{mpsc, oneshot, watch};

use crate::cluster::load_balancer::LoadBalancer;
use crate::cluster::ServiceDiscoveryTypedAddress;
use crate::config::{Config, ConnectionConfig, DynamicResources, EndPoint, Node};
use crate::xds::ads_client::{AdsClient, ClusterUpdate, ExecutionResult};

/// ClusterManager knows about all clusters and endpoints.
pub struct ClusterManager {
    load_balancer: LoadBalancer,
}

#[derive(Debug)]
pub enum InitializeError {
    Message(String),
}

impl fmt::Display for InitializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self))
    }
}

impl std::error::Error for InitializeError {}

pub enum InitializedClusterManager {
    Ads(
        Arc<RwLock<ClusterManager>>,
        oneshot::Receiver<ExecutionResult>,
    ),
    Static(Arc<RwLock<ClusterManager>>),
}

impl ClusterManager {
    /// Returns a list of endpoints chosen by a load balancer.
    pub fn choose_endpoints(&self) -> Vec<EndPoint> {
        self.load_balancer.choose_endpoints()
    }

    /// Creates and initializes a `ClusterManager` that is backed by the
    /// mechanism specified in config - if `dynamic_resources` are provided
    /// in the config then the returned `ClusterManager` is backed by ADS
    /// otherwise it is backed by static information from config.
    pub async fn new_initialized(
        log: Logger,
        config: &Config,
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<InitializedClusterManager, InitializeError> {
        match &config.dynamic_resources {
            Some(resources) => {
                Self::new_ads_initialized(log, resources, config.node.as_ref(), shutdown_rx)
                    .await
                    .map(|(cluster_manager, execution_result_rx)| {
                        InitializedClusterManager::Ads(cluster_manager, execution_result_rx)
                    })
            }
            None => Ok(InitializedClusterManager::Static(Self::new_static(
                &config.connections,
            ))),
        }
    }

    // Returns a new ClusterManager backed by the fixed set of clusters provided in the config.
    pub fn new_static(config: &ConnectionConfig) -> Arc<RwLock<ClusterManager>> {
        Arc::new(RwLock::new(Self::new(
            LoadBalancer::from_connection_config(config),
        )))
    }

    // Returns a ClusterManager backed by an ADS client and a channel
    // to receive the client's execution result after termination.
    async fn new_ads_initialized<'a>(
        log: Logger,
        resources: &'a DynamicResources,
        node: Option<&'a Node>,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> Result<
        (
            Arc<RwLock<ClusterManager>>,
            oneshot::Receiver<ExecutionResult>,
        ),
        InitializeError,
    > {
        let DynamicResources::AdsConfig { server_uri } = resources;
        let server_uri = server_uri.clone();
        let node_id = node.map(|node| node.id.clone()).unwrap_or_default();

        let (cluster_updates_tx, mut cluster_updates_rx) = mpsc::channel::<ClusterUpdate>(10000);
        let (execution_result_tx, execution_result_rx) = oneshot::channel::<ExecutionResult>();
        Self::spawn_ads_client(
            log.clone(),
            node_id,
            server_uri,
            cluster_updates_tx,
            execution_result_tx,
            shutdown_rx.clone(),
        );

        // Initial cluster warming - wait to receive the first set of clusters
        // from the server before we can start to receive any traffic.
        let cluster_update =
            Self::receive_initial_cluster_update(&mut cluster_updates_rx, &mut shutdown_rx).await?;

        let cluster_manager = Arc::new(RwLock::new(Self::new(
            Self::create_load_balancer_from_cluster_update(cluster_update),
        )));

        Self::spawn_updater(
            log.clone(),
            cluster_manager.clone(),
            cluster_updates_rx,
            shutdown_rx.clone(),
        );

        Ok((cluster_manager, execution_result_rx))
    }

    fn create_load_balancer_from_cluster_update(update: ClusterUpdate) -> LoadBalancer {
        // TODO: Extract and use the lb policies from EDS response.
        //  For now use default policy if XDS is enabled.
        let policy_name = None;

        // TODO: Add support for multi-cluster load balancing.
        //  For now we always load balance across all endpoints regardless of cluster/locality.
        let endpoints = update
            .into_iter()
            .map(|(_, cluster)| {
                cluster
                    .localities
                    .into_iter()
                    .map(|(_, endpoints)| endpoints.endpoints)
            })
            .flatten()
            .flatten()
            .filter_map(|endpoint| match endpoint.address {
                ServiceDiscoveryTypedAddress::Static(address) => Some(address),
                // TODO: Add support for endpoints with other service discovery types.
                //  For now we always ignore endpoints with non-static addresses.
                _ => None,
            })
            // TODO: Check if EDS endpoints have names and use them here
            .map(|address| EndPoint::new("EDS endpoint".into(), address, vec![]))
            .collect();

        LoadBalancer::new(&policy_name, endpoints)
    }

    // Spawns a task that runs an ADS client. Cluster updates from the client
    // as well as execution result after termination are sent on the provided channels.
    fn spawn_ads_client(
        log: Logger,
        node_id: String,
        server_addresses: Vec<String>,
        cluster_updates_tx: mpsc::Sender<ClusterUpdate>,
        execution_result_tx: oneshot::Sender<ExecutionResult>,
        shutdown_rx: watch::Receiver<()>,
    ) {
        tokio::spawn(async move {
            let result = AdsClient
                .run(
                    log.clone(),
                    node_id,
                    server_addresses,
                    cluster_updates_tx,
                    shutdown_rx,
                )
                .await;
            execution_result_tx
                .send(result)
                .map_err(|_err| warn!(log, "failed to send ADS client execution result on channel"))
                .ok();
        });
    }

    // Waits until it receives a cluster update from the given channel.
    async fn receive_initial_cluster_update(
        cluster_updates_rx: &mut mpsc::Receiver<ClusterUpdate>,
        shutdown_rx: &mut watch::Receiver<()>,
    ) -> Result<ClusterUpdate, InitializeError> {
        tokio::select! {
            update = cluster_updates_rx.recv() => {
                match update {
                    Some(update) => {
                        Ok(update)
                    }
                    None => {
                        // Sender has dropped - so we can't initialize properly.
                        Err(InitializeError::Message("failed to receive initial cluster - sender dropped the channel".into()))
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                Err(InitializeError::Message("failed to receive initial cluster - received shutdown signal".into()))
            },
        }
    }

    // Spawns a task to run a loop that receives cluster updates
    // and updates the ClusterManager's state in turn.
    fn spawn_updater(
        log: Logger,
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
                                let load_balancer = Self::create_load_balancer_from_cluster_update(update);
                                info!(log, "received cluster update");
                                cluster_manager.write().update(load_balancer);
                            }
                            None => {
                                info!(log, "exiting cluster update receive loop because sender dropped the channel.");
                                return;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!(log, "exiting cluster update receive loop because sender a shutdown signal was received.");
                        return;
                    },
                }
            }
        });
    }

    fn new(load_balancer: LoadBalancer) -> Self {
        ClusterManager { load_balancer }
    }

    fn update(&mut self, load_balancer: LoadBalancer) {
        self.load_balancer = load_balancer;
    }
}
