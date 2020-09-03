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
use tokio::sync::{mpsc, watch};
use tonic::Request;

use crate::cluster::Cluster;
use crate::xds::cluster::ClusterManager;
use crate::xds::envoy::config::core::v3::Node;
use crate::xds::envoy::service::discovery::v3::{
    aggregated_discovery_service_client, DiscoveryRequest,
};
use crate::xds::{CLUSTER_TYPE, ENDPOINT_TYPE};
use slog::{error, info, Logger};
use std::collections::HashMap;

/// AdsClient is a client for an ADS control plane server.
struct AdsClient;

#[derive(Debug)]
enum Error {
    BackoffLimitExceeded,
    Message(String),
}

struct RunRpcLoopArgs<'a> {
    log: Logger,
    server_addr: String,
    node_id: String,
    cluster_manager: ClusterManager,
    discovery_req_rx: &'a mut mpsc::Receiver<DiscoveryRequest>,
    shutdown_rx: watch::Receiver<bool>,
}

enum RpcLoopResult {
    InitialConnectFailure(ClusterManager, tonic::transport::Error),
    Success(ClusterManager),
    RecvFailure(ClusterManager, tonic::Status),
    NonRecoverableFailure(&'static str, Box<dyn std::error::Error + Send + Sync>),
}

impl AdsClient {
    // Continuously tracks the state of CDS and EDS resources on the specified ADS
    // server, sending summarized cluster updates on the provided channel.
    async fn run(
        &self,
        log: Logger,
        server_addr: String,
        node_id: String,
        cluster_updates_tx: mpsc::Sender<HashMap<String, Cluster>>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Result<(), Error> {
        // TODO: Reset backoff timer when we next do a successful RPC.
        let mut backoff = ExponentialBackoff::<SystemClock>::default();

        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DiscoveryRequest>(100);
        let mut cluster_manager =
            ClusterManager::new(log.clone(), cluster_updates_tx, discovery_req_tx);

        // Run the client in a loop - if the stream fails, we try to re-connect.
        loop {
            // Clear any stale state before (re)connecting.
            cluster_manager.on_reconnect();

            let args = RunRpcLoopArgs {
                log: log.clone(),
                server_addr: server_addr.clone(),
                node_id: node_id.clone(),
                cluster_manager,
                discovery_req_rx: &mut discovery_req_rx,
                shutdown_rx: shutdown_rx.clone(),
            };

            tokio::select! {
                result = run_rpc_loop(args) => {
                    match result {
                        RpcLoopResult::Success(_) => return Ok(()),
                        RpcLoopResult::NonRecoverableFailure(msg, err) => {
                            error!(log, "{}", msg);
                            return Err(Error::Message(format!("{:?}", err)));
                        }
                        RpcLoopResult::InitialConnectFailure(cm, err) => {
                            cluster_manager = cm;
                            Self::log_error_and_backoff(
                                &log,
                                format!("connect failure: {:?}", err), &mut backoff
                            ).await?;
                        }
                        RpcLoopResult::RecvFailure(cm, status) => {
                            cluster_manager = cm;
                            Self::log_error_and_backoff(
                                &log,
                                format!("receive response failure: {:?}", status), &mut backoff
                            ).await?;
                        }
                    }
                },

                _ = shutdown_rx.recv() => {
                    return Ok(())
                },
            }
        }
    }

    async fn log_error_and_backoff<C: Clock>(
        log: &Logger,
        error_msg: String,
        backoff: &mut ExponentialBackoff<C>,
    ) -> Result<(), Error> {
        error!(log, "{}", error_msg);
        let delay = backoff
            .next_backoff()
            .ok_or_else(|| Error::BackoffLimitExceeded)?;
        info!(log, "retrying in {:?}...", delay);
        tokio::time::delay_for(delay).await;
        Ok(())
    }
}

// Runs two loops concurrently executing the XDS protocol together with a
// ClusterManager. One loop receives responses from the ADS server,
// forwarding them to the ClusterManager and another that waits for
// DiscoveryRequest ACKS/NACKS from the ClusterManager, forwarding them to
// the ADS server.
async fn run_rpc_loop(args: RunRpcLoopArgs<'_>) -> RpcLoopResult {
    let RunRpcLoopArgs {
        log,
        server_addr,
        node_id,
        mut cluster_manager,
        discovery_req_rx,
        mut shutdown_rx,
    } = args;
    let mut client =
        match aggregated_discovery_service_client::AggregatedDiscoveryServiceClient::connect(
            server_addr,
        )
        .await
        {
            Ok(client) => client,
            Err(err) => return RpcLoopResult::InitialConnectFailure(cluster_manager, err),
        };

    let (mut rpc_tx, rpc_rx) = mpsc::channel::<DiscoveryRequest>(100);

    // Start a task to run the receive loop.
    let recv_log = log.clone();
    let mut recv_loop_join_handle = tokio::spawn(async move {
        let log = recv_log;
        let mut response_stream = match client
            .stream_aggregated_resources(Request::new(rpc_rx))
            .await
        {
            Ok(response) => response.into_inner(),
            Err(err) => return RpcLoopResult::RecvFailure(cluster_manager, err),
        };

        loop {
            tokio::select! {
                response = response_stream.message() => {
                    let response = match response {
                        Ok(None) => return RpcLoopResult::Success(cluster_manager),
                        Err(err) => return RpcLoopResult::RecvFailure(cluster_manager, err),
                        Ok(Some(response)) => response
                    };

                    info!(log, "=> {url}, version={version}, nonce={nonce}, nitems={count}", url = &response.type_url, version = &response.version_info, count = response.resources.len(), nonce = &response.nonce);

                    if response.type_url == CLUSTER_TYPE {
                        cluster_manager.on_cluster_response(response).await;
                    } else if response.type_url == ENDPOINT_TYPE {
                        cluster_manager.on_cluster_load_assignment_response(response).await;
                    } else {
                        error!(log, "Unexpected resource with type_url={:?}", response.type_url);
                    }
                }

                _ = shutdown_rx.recv() => {
                    return RpcLoopResult::Success(cluster_manager)
                }
            }
        }
    });

    // Fetch the initial set of clusters.
    match rpc_tx
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
    {
        Ok(_) => (),
        // An error sending means we have no listener on the other side which
        // would be due to a bug if we're not already shutting down.
        Err(err) => {
            return RpcLoopResult::NonRecoverableFailure(
                "failed to send initial discovery request on channel",
                Box::new(err),
            )
        }
    };

    // Run the send request loop on the current task.
    loop {
        tokio::select! {
            recv_loop_result = &mut recv_loop_join_handle =>
                return recv_loop_result.unwrap_or_else(|err|
                    RpcLoopResult::NonRecoverableFailure(
                        "response loop task failed", Box::new(err))),

            request_loop_result = discovery_req_rx.recv() => {
                if let Some(req) = request_loop_result {
                    info!(log, "Sending rpc discovery request {:?}", req);
                    match rpc_tx.send(req).await {
                        Ok(_) => (),
                        Err(err) => return RpcLoopResult::NonRecoverableFailure(
                            "failed to send discovery request on channel", Box::new(err)),
                    }
                } else {
                    break;
                }
            }
        }
    }

    // Awaiting the JoinHandle future here is safe since we can be sure that it has
    // not yet terminated - if it had we would have returned the result immediately.
    recv_loop_join_handle.await.unwrap_or_else(|err| {
        RpcLoopResult::NonRecoverableFailure("response loop task failed", Box::new(err))
    })
}
