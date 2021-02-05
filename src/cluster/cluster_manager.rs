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
// and we will need to acquire a read lock with every packet that is processed
// to be able to capture the current endpoint state and pass it to Filters.
use parking_lot::RwLock;
use slog::{debug, info, o, warn, Logger};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::{fmt, sync::Arc};
use tokio::sync::{mpsc, oneshot, watch};

use crate::cluster::Endpoint;
use crate::config::{EmptyListError, EndPoint, Endpoints, ManagementServer, UpstreamEndpoints};
use crate::extensions::filter_manager::ListenerManagerArgs;
use crate::extensions::FilterRegistry;
use crate::xds::ads_client::{AdsClient, ClusterUpdate, ExecutionResult};

/// The max size of queue that provides updates from the XDS layer to the [`ClusterManager`].
const CLUSTER_UPDATE_QUEUE_SIZE: usize = 1000;

pub(crate) type SharedClusterManager = Arc<RwLock<ClusterManager>>;

/// ClusterManager knows about all clusters and endpoints.
pub(crate) struct ClusterManager {
    endpoints: Option<Endpoints>,
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
    fn new(endpoints: Option<Endpoints>) -> Self {
        Self { endpoints }
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
    pub fn fixed(endpoints: Vec<Endpoint>) -> SharedClusterManager {
        // TODO: Return a result rather than unwrap.
        Arc::new(RwLock::new(Self::new(Some(
            Endpoints::new(endpoints)
                .expect("endpoints list in config should be validated non-empty"),
        ))))
    }

    /// Returns a ClusterManager backed by a set of XDS servers.
    /// This function starts an XDS client in the background that talks to
    /// one of the provided servers.
    /// Multiple management servers can be provided for redundancy - the servers will be
    /// connected to in turn only in the case of failure.
    /// The set of clusters is continuously updated based on responses
    /// from the XDS server.
    /// The returned contains the XDS client's execution result after termination.
    pub fn dynamic(
        base_logger: Logger,
        cluster_update: ClusterUpdate,
        cluster_updates_rx: mpsc::Receiver<ClusterUpdate>,
        shutdown_rx: watch::Receiver<()>,
    ) -> SharedClusterManager {
        let log = base_logger.new(o!("source" => "cluster::ClusterManager"));

        let cluster_manager = Arc::new(RwLock::new(Self::new(Self::create_endpoints_from_update(
            cluster_update,
        ))));

        // Start a task in the background to receive cluster updates
        // and update the cluster manager's cluster set in turn.
        Self::spawn_updater(
            log.clone(),
            cluster_manager.clone(),
            cluster_updates_rx,
            shutdown_rx,
        );

        cluster_manager
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
                    .map(|(_, endpoints)| {
                        endpoints
                            .endpoints
                            .into_iter()
                            .map(|ep| Endpoint::from_address(ep.address))
                    })
                    .flatten();
                endpoints.extend(cluster_endpoints);

                endpoints
            });

        match Endpoints::new(endpoints) {
            Ok(endpoints) => Some(endpoints),
            Err(EmptyListError) => None,
        }
    }

    // Spawns a task that runs an ADS client. Cluster updates from the client
    // as well as execution result after termination are sent on the provided channels.
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
                                let update = Self::create_endpoints_from_update(update);
                                debug!(log, "Received a cluster update.");
                                cluster_manager.write().update(update);
                            }
                            None => {
                                warn!(log, "Exiting cluster update receive loop because the sender dropped the channel.");
                                return;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        debug!(log, "Exiting cluster update receive loop because a shutdown signal was received.");
                        return;
                    },
                }
            }
        });
    }
}
