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

use backoff::{backoff::Backoff, exponential::ExponentialBackoff, Clock, SystemClock};
use slog::{error, info, Logger};
use std::collections::HashMap;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tonic::{
    transport::{channel::Channel as TonicChannel, Error as TonicError},
    Request,
};

use crate::cluster::Cluster;
use crate::xds::cluster::ClusterManager;
use crate::xds::envoy::config::core::v3::Node;
use crate::xds::envoy::service::discovery::v3::{
    aggregated_discovery_service_client::AggregatedDiscoveryServiceClient, DiscoveryRequest,
};
use crate::xds::{CLUSTER_TYPE, ENDPOINT_TYPE};

/// AdsClient is a client that can talk to an ADS server.
pub struct AdsClient;

// Represents the required arguments to start an rpc session with a server.
struct RpcSessionArgs<'a> {
    log: Logger,
    server_addr: String,
    node_id: String,
    cluster_manager: ClusterManager,
    discovery_req_rx: &'a mut mpsc::Receiver<DiscoveryRequest>,
    shutdown_rx: watch::Receiver<()>,
}

enum RpcSessionError {
    InitialConnect(ClusterManager, TonicError),
    Receive(ClusterManager, tonic::Status),
    NonRecoverable(&'static str, Box<dyn std::error::Error + Send + Sync>),
}

// Represents the outcome of an rpc session with a server.
type RpcSessionResult = Result<ClusterManager, RpcSessionError>;

// Represents an error encountered during a client execution.
#[derive(Debug)]
pub enum ExecutionError {
    BackoffLimitExceeded,
    Message(String),
}

// Represents a full snapshot the all clusters.
pub type ClusterUpdate = HashMap<String, Cluster>;

// Represents the result of a client execution.
pub type ExecutionResult = Result<(), ExecutionError>;

impl AdsClient {
    // Continuously tracks CDS and EDS resources on an ADS server,
    // sending summarized cluster updates on the provided channel.
    pub async fn run(
        self,
        log: Logger,
        node_id: String,
        server_addresses: Vec<String>,
        cluster_updates_tx: mpsc::Sender<ClusterUpdate>,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> ExecutionResult {
        // TODO: Reset backoff timer when we next do a successful RPC.
        let mut backoff = ExponentialBackoff::<SystemClock>::default();

        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cluster_manager =
            ClusterManager::new(log.clone(), cluster_updates_tx, discovery_req_tx);

        // Run the client in a loop.
        // If the connection fails, we retry (with another server if available).
        let mut next_server_index = 0;
        loop {
            // Clear any stale state before (re)connecting.
            cluster_manager.on_reconnect();

            // Pick a server to talk to.
            let server_addr = {
                let server_addr = server_addresses
                    .get(next_server_index % server_addresses.len())
                    .cloned()
                    // We have previously validated that a config provides at least one
                    // server address so this default value shouldn't be necessary.
                    .unwrap_or_else(|| "127.0.0.1:18000".into());
                next_server_index += 1;
                server_addr
            };

            let args = RpcSessionArgs {
                log: log.clone(),
                server_addr: server_addr.clone(),
                node_id: node_id.clone(),
                cluster_manager,
                discovery_req_rx: &mut discovery_req_rx,
                shutdown_rx: shutdown_rx.clone(),
            };

            tokio::select! {
                result = Self::run_rpc_session(args) => {
                    match result {
                        Ok(_) => return Ok(()),
                        Err(RpcSessionError::NonRecoverable(msg, err)) => {
                            error!(log, "{}", msg);
                            return Err(ExecutionError::Message(format!("{:?}", err)));
                        }
                        Err(RpcSessionError::InitialConnect(cm, err)) => {
                            cluster_manager = cm;
                            Self::log_error_and_backoff(
                                &log,
                                format!("unable to connect to the XDS server at {}: {:?}", server_addr, err), &mut backoff
                            ).await?;
                        }
                        Err(RpcSessionError::Receive(cm, status)) => {
                            cluster_manager = cm;
                            Self::log_error_and_backoff(
                                &log,
                                format!("failed to receive from XDS server {}: {:?}", server_addr,status), &mut backoff
                            ).await?;
                        }
                    }
                },

                _ = shutdown_rx.recv() => {
                    info!(log, "stopping client execution - received shutdown signal.");
                    return Ok(())
                },
            }
        }
    }

    // Executes an RPC session with a server.
    // A session consists of two concurrent rpc loops executing the XDS protocol
    // together with a ClusterManager. One loop (receive loop) receives
    // responses from the server, forwarding them to the ClusterManager
    // while the other loop (send loop) waits for DiscoveryRequest ACKS/NACKS
    // from the ClusterManager, forwarding them to the server.
    async fn run_rpc_session(args: RpcSessionArgs<'_>) -> RpcSessionResult {
        let RpcSessionArgs {
            log,
            server_addr,
            node_id,
            cluster_manager,
            discovery_req_rx,
            shutdown_rx,
        } = args;
        let client = match AggregatedDiscoveryServiceClient::connect(server_addr).await {
            Ok(client) => client,
            Err(err) => return Err(RpcSessionError::InitialConnect(cluster_manager, err)),
        };

        let (mut rpc_tx, rpc_rx) = mpsc::channel::<DiscoveryRequest>(100);

        // Spawn a task that runs the receive loop.
        let mut recv_loop_join_handle =
            Self::run_receive_loop(log.clone(), client, rpc_rx, cluster_manager, shutdown_rx);

        // Fetch the initial set of clusters.
        Self::send_initial_cds_request(node_id, &mut rpc_tx).await?;

        // Run the send loop on the current task.
        loop {
            tokio::select! {
                // Monitor the receive loop task, if it fails then there is
                // no need to remain in the send loop so we exit.
                recv_loop_result = &mut recv_loop_join_handle =>
                    return recv_loop_result.unwrap_or_else(|err|
                        Err(RpcSessionError::NonRecoverable(
                            "receive loop encountered an error", Box::new(err)))),

                req = discovery_req_rx.recv() => {
                    if let Some(req) = req {
                        info!(log, "sending rpc discovery request {:?}", req);
                        rpc_tx.send(req)
                            .await
                            .map_err(|err| RpcSessionError::NonRecoverable(
                                "failed to send discovery request on channel",
                                Box::new(err))
                            )?;
                    } else {
                        info!(log, "exiting send loop");
                        break;
                    }
                }
            }
        }

        // Awaiting the JoinHandle future here is safe since we can be sure that it has
        // not yet terminated - if it had we would have returned the result immediately.
        recv_loop_join_handle.await.unwrap_or_else(|err| {
            Err(RpcSessionError::NonRecoverable(
                "receive loop encountered an error",
                Box::new(err),
            ))
        })
    }

    async fn send_initial_cds_request(
        node_id: String,
        rpc_tx: &mut mpsc::Sender<DiscoveryRequest>,
    ) -> Result<(), RpcSessionError> {
        rpc_tx
            .send(DiscoveryRequest {
                version_info: "".into(),
                node: Some(Node {
                    id: node_id,
                    cluster: "".into(),
                    metadata: None,
                    locality: None,
                    user_agent_name: "quilkin".into(),
                    extensions: vec![],
                    client_features: vec![],
                    listening_addresses: vec![],
                    user_agent_version_type: None,
                }),
                resource_names: vec![], // Wildcard mode.
                type_url: CLUSTER_TYPE.into(),
                response_nonce: "".into(),
                error_detail: None,
            })
            .await
            .map_err(|err|
                // An error sending means we have no listener on the other side which
                // would likely be a bug if we're not already shutting down.
                RpcSessionError::NonRecoverable(
                    "failed to send initial CDS discovery request on channel",
                    Box::new(err),
                ))
    }

    // Spawns a task that runs a receive loop.
    fn run_receive_loop(
        log: Logger,
        mut client: AggregatedDiscoveryServiceClient<TonicChannel>,
        rpc_rx: mpsc::Receiver<DiscoveryRequest>,
        mut cluster_manager: ClusterManager,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> JoinHandle<RpcSessionResult> {
        tokio::spawn(async move {
            let mut response_stream = match client
                .stream_aggregated_resources(Request::new(rpc_rx))
                .await
            {
                Ok(response) => response.into_inner(),
                Err(err) => return Err(RpcSessionError::Receive(cluster_manager, err)),
            };

            loop {
                tokio::select! {
                    response = response_stream.message() => {
                        let response = match response {
                            Ok(None) => {
                                // No more messages on the connection.
                                info!(log, "exiting receive loop - response stream closed.");
                                return Ok(cluster_manager)
                            },
                            Err(err) => return Err(RpcSessionError::Receive(cluster_manager, err)),
                            Ok(Some(response)) => response
                        };

                        if response.type_url == CLUSTER_TYPE {
                            cluster_manager.on_cluster_response(response).await;
                        } else if response.type_url == ENDPOINT_TYPE {
                            cluster_manager.on_cluster_load_assignment_response(response).await;
                        } else {
                            error!(log, "Unexpected resource with type_url={:?}", response.type_url);
                        }
                    }

                    _ = shutdown_rx.recv() => {
                        info!(log, "exiting receive loop - received shutdown signal.");
                        return Ok(cluster_manager)
                    }
                }
            }
        })
    }

    async fn log_error_and_backoff<C: Clock>(
        log: &Logger,
        error_msg: String,
        backoff: &mut ExponentialBackoff<C>,
    ) -> Result<(), ExecutionError> {
        error!(log, "{}", error_msg);
        let delay = backoff
            .next_backoff()
            .ok_or_else(|| ExecutionError::BackoffLimitExceeded)?;
        info!(log, "retrying in {:?}", delay);
        tokio::time::delay_for(delay).await;
        Ok(())
    }
}
