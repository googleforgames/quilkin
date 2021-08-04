/*
 * Copyright 2021 Google LLC
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
use crate::config::{Endpoints, ManagementServer};
use crate::filters::{
    manager::{FilterManager, ListenerManagerArgs, SharedFilterManager},
    FilterChain, FilterRegistry,
};
use crate::xds::ads_client::{
    AdsClient, ClusterUpdate, ExecutionResult, UPDATES_CHANNEL_BUFFER_SIZE,
};
use prometheus::Registry;
use slog::{debug, o, warn, Logger};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

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
        metrics_registry: &Registry,
        endpoints: Endpoints,
        filter_chain: Arc<FilterChain>,
    ) -> Result<StaticResourceManagers, InitializeError> {
        Ok(Self {
            cluster_manager: ClusterManager::fixed(metrics_registry, endpoints)
                .map_err(|err| InitializeError::Message(format!("{:?}", err)))?,
            filter_manager: FilterManager::fixed(filter_chain),
        })
    }
}

/// Contains arguments to the `spawn_ads_client` function.
struct SpawnAdsClient {
    log: Logger,
    metrics_registry: Registry,
    node_id: String,
    management_servers: Vec<ManagementServer>,
    cluster_updates_tx: mpsc::Sender<ClusterUpdate>,
    listener_manager_args: ListenerManagerArgs,
    execution_result_tx: oneshot::Sender<ExecutionResult>,
    shutdown_rx: watch::Receiver<()>,
}

impl DynamicResourceManagers {
    pub(super) async fn new(
        base_logger: Logger,
        xds_node_id: String,
        metrics_registry: Registry,
        filter_registry: FilterRegistry,
        management_servers: Vec<ManagementServer>,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> Result<DynamicResourceManagers, InitializeError> {
        let log = base_logger.new(o!("source" => "server::DynamicResourceManager"));

        let (cluster_updates_tx, mut cluster_updates_rx) = Self::cluster_updates_channel();
        let (filter_chain_updates_tx, mut filter_chain_updates_rx) =
            Self::filter_chain_updates_channel();

        let listener_manager_args = ListenerManagerArgs::new(
            metrics_registry.clone(),
            filter_registry,
            filter_chain_updates_tx,
        );

        let (execution_result_tx, execution_result_rx) = oneshot::channel::<ExecutionResult>();
        Self::spawn_ads_client(SpawnAdsClient {
            log: log.clone(),
            metrics_registry: metrics_registry.clone(),
            node_id: xds_node_id,
            management_servers,
            cluster_updates_tx,
            listener_manager_args,
            execution_result_tx,
            shutdown_rx: shutdown_rx.clone(),
        })?;

        // Initial cluster warming - wait to receive the initial LDS and CDS resources
        // from the XDS server before we start receiving any traffic.
        debug!(log, "Waiting to receive initial cluster update.");
        let (cluster_update, execution_result_rx) = Self::receive_update(
            &mut cluster_updates_rx,
            execution_result_rx,
            &mut shutdown_rx,
        )
        .await?;
        debug!(log, "Received initial cluster update.");

        debug!(log, "Waiting to receive initial filter chain update.");
        let (filter_chain_update, execution_result_rx) = Self::receive_update(
            &mut filter_chain_updates_rx,
            execution_result_rx,
            &mut shutdown_rx,
        )
        .await?;
        debug!(log, "Received initial filter chain update.");

        let cluster_manager = ClusterManager::dynamic(
            base_logger.new(o!("source" => "ClusterManager")),
            &metrics_registry,
            cluster_update,
            cluster_updates_rx,
            shutdown_rx.clone(),
        )
        .map_err(|err| InitializeError::Message(format!("{:?}", err)))?;

        let filter_manager = FilterManager::dynamic(
            base_logger.new(o!("source" => "FilterManager")),
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
    fn spawn_ads_client(args: SpawnAdsClient) -> Result<(), InitializeError> {
        let SpawnAdsClient {
            log,
            metrics_registry,
            node_id,
            management_servers,
            cluster_updates_tx,
            listener_manager_args,
            execution_result_tx,
            shutdown_rx,
        } = args;

        let client = AdsClient::new(log.clone(), &metrics_registry).map_err(|err| {
            InitializeError::Message(format!("failed to initialize xDS client: {:?}", err))
        })?;
        tokio::spawn(async move {
            let result = client
                .run(
                    node_id,
                    management_servers,
                    cluster_updates_tx,
                    listener_manager_args,
                    shutdown_rx,
                )
                .await;
            execution_result_tx
                .send(result)
                .map_err(|_err| warn!(log, "Failed to send ADS client execution result on channel"))
                .ok();
        });

        Ok(())
    }

    // Waits until it receives a cluster update from the given channel.
    // This also takes in the execution result receiver - while we're waiting for
    // an update, if the client exits prematurely, we return its execution error.
    async fn receive_update<T>(
        updates_rx: &mut mpsc::Receiver<T>,
        execution_result_rx: oneshot::Receiver<ExecutionResult>,
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
                        if let Ok(Ok(Err(execution_error))) = tokio::time::timeout(Duration::from_millis(1000), execution_result_rx).await {
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
        mpsc::channel(UPDATES_CHANNEL_BUFFER_SIZE)
    }

    fn filter_chain_updates_channel() -> (
        mpsc::Sender<Arc<FilterChain>>,
        mpsc::Receiver<Arc<FilterChain>>,
    ) {
        mpsc::channel(UPDATES_CHANNEL_BUFFER_SIZE)
    }
}
#[cfg(test)]
mod tests {

    use super::DynamicResourceManagers;
    use crate::cluster::cluster_manager::InitializeError;
    use crate::config::ManagementServer;
    use crate::filters::{manager::ListenerManagerArgs, FilterRegistry};
    use crate::test_utils::logger;
    use crate::xds::ads_client::ExecutionError;

    use std::time::Duration;

    use crate::proxy::resource_manager::SpawnAdsClient;
    use prometheus::Registry;
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;
    use tokio::sync::watch;
    use tokio::time;

    #[tokio::test]
    async fn dynamic_resource_manager_receive_update() {
        let (updates_tx, mut updates_rx) = mpsc::channel(10);
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(());
        let (_execution_tx, execution_result_rx) = oneshot::channel();

        updates_tx.send(42).await.unwrap();

        let (result, _) = DynamicResourceManagers::receive_update(
            &mut updates_rx,
            execution_result_rx,
            &mut shutdown_rx,
        )
        .await
        .unwrap();

        assert_eq!(42, result);
    }

    #[tokio::test]
    async fn dynamic_resource_manager_shutdown_task_on_system_shutdown() {
        // If a shutdown is triggered, shutdown the task.
        let (_updates_tx, mut updates_rx) = mpsc::channel::<usize>(10);
        let (shutdown_tx, mut shutdown_rx) = watch::channel(());
        let (_execution_tx, execution_result_rx) = oneshot::channel();

        // Send a shutdown signal.
        shutdown_tx.send(()).unwrap();

        // We should exit with an error.
        let result = DynamicResourceManagers::receive_update(
            &mut updates_rx,
            execution_result_rx,
            &mut shutdown_rx,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dynamic_resource_manager_shutdown_task_on_sender_half_closed() {
        // If the sender half of the updates channel is dropped, shutdown the task
        // since we can never receive an update after that.
        let (updates_tx, mut updates_rx) = mpsc::channel::<usize>(10);
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(());
        let (_execution_tx, execution_result_rx) = oneshot::channel();

        // Drop the sender half.
        drop(updates_tx);

        // We should exit with an error since we now can never receive an update.
        let result = DynamicResourceManagers::receive_update(
            &mut updates_rx,
            execution_result_rx,
            &mut shutdown_rx,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn dynamic_resource_manager_return_execution_error_on_sender_half_closed() {
        // If the sender half of the updates channel is dropped, check the ExecutionResult
        // channel for any error that might hint at why it was dropped and if one exists,
        // return it.
        let (updates_tx, mut updates_rx) = mpsc::channel::<usize>(10);
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(());
        let (execution_result_tx, execution_result_rx) = oneshot::channel();

        // Leave an error ExecutionResult before dropping the updates channel.
        execution_result_tx
            .send(Err(ExecutionError::Message("Boo!".into())))
            .unwrap();

        // Drop the sender half of the updates channel.
        drop(updates_tx);

        // When exiting due to the sending channel being dropped, we first check
        // for an execution result error and return that instead.
        match DynamicResourceManagers::receive_update(
            &mut updates_rx,
            execution_result_rx,
            &mut shutdown_rx,
        )
        .await
        {
            Err(InitializeError::Message(msg)) if msg.contains("Boo!") => {}
            unexpected => unreachable!(format!("{:?}", unexpected)),
        }
    }

    #[tokio::test]
    async fn dynamic_resource_manager_return_execution_error() {
        // Check that we can return ExecutionResults on the channel.
        // In this case, the client failed to start due to a malformed server address.
        let (filter_chain_updates_tx, _filter_chain_updates_rx) = mpsc::channel(10);
        let (cluster_updates_tx, _cluster_updates_rx) = mpsc::channel(10);
        let (execution_result_tx, execution_result_rx) = oneshot::channel();
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        DynamicResourceManagers::spawn_ads_client(SpawnAdsClient {
            log: logger(),
            metrics_registry: Registry::default(),
            node_id: "id".into(),
            management_servers: vec![ManagementServer {
                address: "invalid-address".into(),
            }],
            cluster_updates_tx,
            listener_manager_args: ListenerManagerArgs::new(
                Registry::default(),
                FilterRegistry::default(),
                filter_chain_updates_tx,
            ),
            execution_result_tx,
            shutdown_rx,
        })
        .unwrap();

        let err = time::timeout(Duration::from_secs(5), execution_result_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();

        assert!(format!("{:?}", err).to_lowercase().contains("invalid url"));
    }
}
