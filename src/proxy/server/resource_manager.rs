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

use crate::cluster::cluster_manager::{ClusterManager, InitializeError, SharedClusterManager};
use crate::cluster::Endpoint;
use crate::config::ManagementServer;
use crate::extensions::filter_manager::{FilterManager, ListenerManagerArgs, SharedFilterManager};
use crate::extensions::{FilterChain, FilterRegistry};
use crate::xds::ads_client::{AdsClient, ClusterUpdate, ExecutionResult};
use slog::{info, o, warn, Logger};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch};

/// The max size of queue of the channel that provides cluster updates from the XDS layer.
const CLUSTER_UPDATE_QUEUE_SIZE: usize = 1000;

/// The max size of queue of the channel that provides filter updates from the XDS layer.
const FILTER_CHAIN_UPDATE_QUEUE_SIZE: usize = 500;

/// Contains resource managers for fixed cluster/filter etc resources.
pub(super) struct StaticResourceManagers {
    pub(super) cluster_manager: SharedClusterManager,
    pub(super) filter_manager: SharedFilterManager,
}

/// Contains resource managers for XDS resources.
pub(super) struct DynamicResourceManagers {
    pub(super) cluster_manager: SharedClusterManager,
    pub(super) filter_manager: SharedFilterManager,
    pub(super) execution_result_rx: oneshot::Receiver<ExecutionResult>,
}

impl StaticResourceManagers {
    pub(super) fn new(
        base_logger: Logger,
        endpoints: Vec<Endpoint>,
        filter_chain: Arc<FilterChain>,
    ) -> StaticResourceManagers {
        Self {
            cluster_manager: ClusterManager::fixed(endpoints),
            filter_manager: FilterManager::fixed(base_logger, filter_chain),
        }
    }
}

impl DynamicResourceManagers {
    pub(super) async fn new(
        base_logger: Logger,
        xds_node_id: String,
        filter_registry: Arc<FilterRegistry>,
        management_servers: Vec<ManagementServer>,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> Result<DynamicResourceManagers, InitializeError> {
        let log = base_logger.new(o!("source" => "server::DynamicResourceManager"));

        let (cluster_updates_tx, mut cluster_updates_rx) = Self::cluster_updates_channel();
        let (filter_chain_updates_tx, mut filter_chain_updates_rx) =
            Self::filter_chain_updates_channel();

        let listener_manager_args =
            ListenerManagerArgs::new(filter_registry, filter_chain_updates_tx);

        let (execution_result_tx, execution_result_rx) = oneshot::channel::<ExecutionResult>();
        Self::spawn_ads_client(
            log.clone(),
            xds_node_id,
            management_servers,
            cluster_updates_tx,
            listener_manager_args,
            execution_result_tx,
            shutdown_rx.clone(),
        );

        // Initial cluster warming - wait to receive the initial LDS and CDS resources
        // from the XDS server before we start receiving any traffic.
        info!(log, "Waiting to receive initial cluster update.");
        let (cluster_update, execution_result_rx) = Self::receive_update(
            &mut cluster_updates_rx,
            execution_result_rx,
            &mut shutdown_rx,
        )
        .await?;
        info!(log, "Received initial cluster update.");

        info!(log, "Waiting to receive initial filter chain update.");
        let (filter_chain_update, execution_result_rx) = Self::receive_update(
            &mut filter_chain_updates_rx,
            execution_result_rx,
            &mut shutdown_rx,
        )
        .await?;
        info!(log, "Received initial filter chain update.");

        let cluster_manager = ClusterManager::dynamic(
            base_logger.clone(),
            cluster_update,
            cluster_updates_rx,
            shutdown_rx.clone(),
        );

        let filter_manager = FilterManager::dynamic(
            base_logger.clone(),
            filter_chain_update,
            filter_chain_updates_rx,
            shutdown_rx.clone(),
        );

        Ok(Self {
            cluster_manager,
            filter_manager,
            execution_result_rx,
        })
    }

    // Spawns a task that runs an ADS client.
    // Cluster and Filter updates from the client
    // as well as execution result after termination are sent on the passed-in channels.
    fn spawn_ads_client(
        log: Logger,
        node_id: String,
        management_servers: Vec<ManagementServer>,
        cluster_updates_tx: mpsc::Sender<ClusterUpdate>,
        listener_manager_args: ListenerManagerArgs,
        execution_result_tx: oneshot::Sender<ExecutionResult>,
        shutdown_rx: watch::Receiver<()>,
    ) {
        tokio::spawn(async move {
            let result = AdsClient
                .run(
                    log.clone(),
                    node_id,
                    management_servers,
                    cluster_updates_tx,
                    listener_manager_args,
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
    // This also takes in the execution result receiver - while we're waiting for
    // an update, if the client exits prematurely, we return its execution error.
    async fn receive_update<T>(
        updates_rx: &mut mpsc::Receiver<T>,
        mut execution_result_rx: oneshot::Receiver<ExecutionResult>,
        shutdown_rx: &mut watch::Receiver<()>,
    ) -> Result<(T, oneshot::Receiver<ExecutionResult>), InitializeError> {
        tokio::select! {
            update = updates_rx.recv() => {
                match update {
                    Some(update) => {
                        Ok((update, execution_result_rx))
                    }
                    None => {
                        // Sender has dropped (the client exited prematurely) - so we can't
                        // initialize properly.
                        // Check the client's execution result if exiting was due to some root cause
                        // error and return that error if so. Otherwise return a generic error.
                        if let Ok(Err(execution_error)) = execution_result_rx.try_recv() {
                            Err(InitializeError::Message(format!("failed to receive initial update: {:?}", execution_error)))
                        } else {
                            Err(InitializeError::Message("failed to receive initial update: sender dropped the channel".into()))
                        }
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                Err(InitializeError::Message("failed to receive initial update: received shutdown signal".into()))
            },
        }
    }

    fn cluster_updates_channel() -> (mpsc::Sender<ClusterUpdate>, mpsc::Receiver<ClusterUpdate>) {
        mpsc::channel(CLUSTER_UPDATE_QUEUE_SIZE)
    }

    fn filter_chain_updates_channel() -> (
        mpsc::Sender<Arc<FilterChain>>,
        mpsc::Receiver<Arc<FilterChain>>,
    ) {
        mpsc::channel(FILTER_CHAIN_UPDATE_QUEUE_SIZE)
    }
}
