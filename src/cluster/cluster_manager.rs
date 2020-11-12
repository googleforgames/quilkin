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

// TODO: Allow unused variables since this module is WIP.
#![allow(unused)]

// We use a parking_lot since it's significantly faster under low contention
use parking_lot::RwLock;
use slog::{info, warn, Logger};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::{fmt, sync::Arc};
use tokio::sync::{mpsc, oneshot, watch};

use crate::config::EndPoint;
use crate::xds::ads_client::{AdsClient, ClusterUpdate, ExecutionResult};

/// The max size of queue that provides updates from the XDS layer to the [`ClusterManager`].
const CLUSTER_UPDATE_QUEUE_SIZE: usize = 1000;

type Clusters = HashMap<String, Vec<SocketAddr>>;

/// ClusterManager knows about all clusters and endpoints.
pub struct ClusterManager {
    clusters: Clusters,
}

/// InitializeError is returned with an error message if the
/// [`ClusterManager`] fails to initialize properly.
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

impl ClusterManager {
    fn new(clusters: Clusters) -> Self {
        Self { clusters }
    }

    fn update(&mut self, clusters: Clusters) {
        self.clusters = clusters;
    }

    /// Returns all endpoints known at the time of invocation.
    pub fn get_all_endpoints(&self) -> Vec<EndPoint> {
        self.clusters
            .iter()
            .map(|(name, addresses)| {
                addresses
                    .iter()
                    .map(move |addr| EndPoint::new(name.clone(), *addr, vec![]))
            })
            .flatten()
            .collect()
    }

    /// Returns a ClusterManager backed by the fixed set of clusters provided in the config.
    pub fn fixed(endpoints: &[(String, SocketAddr)]) -> ClusterManager {
        Self::new(
            endpoints
                .iter()
                .cloned()
                .map(|(name, addr)| (name, vec![addr]))
                .collect(),
        )
    }

    /// Returns a ClusterManager backed by a set of XDS servers.
    /// This function starts an XDS client in the background that talks to
    /// one of the provided servers.
    /// Multiple servers are provided for redundancy - the servers will be
    /// connected to in turn only in the case of failure.
    /// The set of clusters is continuously updated based on responses
    /// from the XDS server.
    /// The returned contains the XDS client's execution result after termination.
    async fn dynamic<'a>(
        log: Logger,
        server_addresses: Vec<String>,
        xds_node_id: Option<String>,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> Result<
        (
            Arc<RwLock<ClusterManager>>,
            oneshot::Receiver<ExecutionResult>,
        ),
        InitializeError,
    > {
        let (cluster_updates_tx, mut cluster_updates_rx) =
            mpsc::channel::<ClusterUpdate>(CLUSTER_UPDATE_QUEUE_SIZE);
        let (execution_result_tx, execution_result_rx) = oneshot::channel::<ExecutionResult>();
        Self::spawn_ads_client(
            log.clone(),
            xds_node_id.unwrap_or_default(),
            server_addresses,
            cluster_updates_tx,
            execution_result_tx,
            shutdown_rx.clone(),
        );

        // Initial cluster warming - wait to receive the first set of clusters
        // from the server before we start receiving any traffic.
        let cluster_update =
            Self::receive_initial_cluster_update(&mut cluster_updates_rx, &mut shutdown_rx).await?;

        let cluster_manager = Arc::new(RwLock::new(Self::new(Self::create_clusters_from_update(
            cluster_update,
        ))));

        // Start a task in the background to receive future cluster updates
        // and update the cluster manager's cluster set in turn.
        Self::spawn_updater(
            log.clone(),
            cluster_manager.clone(),
            cluster_updates_rx,
            shutdown_rx.clone(),
        );

        Ok((cluster_manager, execution_result_rx))
    }

    fn create_clusters_from_update(update: ClusterUpdate) -> Clusters {
        update
            .into_iter()
            .map(|(name, cluster)| {
                let addresses = cluster
                    .localities
                    .into_iter()
                    .map(|(_, endpoints)| endpoints.endpoints.into_iter().map(|ep| ep.address))
                    .flatten()
                    .collect::<Vec<_>>();
                (name, addresses)
            })
            .collect()
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

    /// Spawns a task to run a loop that receives cluster updates
    /// and updates the ClusterManager's state in turn.
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
                                let update = Self::create_clusters_from_update(update);
                                info!(log, "received cluster update");
                                cluster_manager.write().update(update);
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
}
