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

use crate::{
    cluster::cluster_manager::{ClusterManager, InitializeError, SharedClusterManager},
    config::ManagementServer,
    endpoint::Endpoints,
    filters::{
        manager::{FilterManager, ListenerManagerArgs, SharedFilterManager},
        FilterChain, FilterRegistry,
    },
    xds::ads_client::{AdsClient, ClusterUpdate, ExecutionResult, UPDATES_CHANNEL_BUFFER_SIZE},
};
use prometheus::Registry;
use slog::{o, warn, Logger};
use std::sync::Arc;
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
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<DynamicResourceManagers, InitializeError> {
        let log = base_logger.new(o!("source" => "server::DynamicResourceManager"));

        let (cluster_updates_tx, cluster_updates_rx) = Self::cluster_updates_channel();
        let (filter_chain_updates_tx, filter_chain_updates_rx) =
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

        let cluster_manager = ClusterManager::dynamic(
            base_logger.new(o!("source" => "ClusterManager")),
            &metrics_registry,
            cluster_updates_rx,
            shutdown_rx.clone(),
        )
        .map_err(|err| InitializeError::Message(format!("{:?}", err)))?;

        let filter_manager = FilterManager::dynamic(
            base_logger.new(o!("source" => "FilterManager")),
            &metrics_registry,
            filter_chain_updates_rx,
            shutdown_rx,
        )
        .map_err(|err| InitializeError::Message(format!("{:?}", err)))?;

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
    use crate::config::ManagementServer;
    use crate::filters::{manager::ListenerManagerArgs, FilterRegistry};
    use crate::test_utils::logger;

    use std::time::Duration;

    use crate::proxy::server::resource_manager::SpawnAdsClient;
    use prometheus::Registry;
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;
    use tokio::sync::watch;
    use tokio::time;

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
