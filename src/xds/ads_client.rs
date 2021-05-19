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

use std::collections::HashMap;

use crate::xds::google::rpc::Status as GrpcStatus;
use backoff::{backoff::Backoff, exponential::ExponentialBackoff, Clock, SystemClock};
use prometheus::{Registry, Result as MetricsResult};
use slog::{debug, error, info, o, warn, Logger};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{channel::Channel as TonicChannel, Error as TonicError},
    Request,
};

use crate::cluster::Cluster;
use crate::config::ManagementServer;
use crate::extensions::filter_manager::ListenerManagerArgs;
use crate::xds::cluster::ClusterManager;
use crate::xds::envoy::config::core::v3::Node;
use crate::xds::envoy::service::discovery::v3::{
    aggregated_discovery_service_client::AggregatedDiscoveryServiceClient, DiscoveryRequest,
};
use crate::xds::listener::ListenerManager;
use crate::xds::metrics::Metrics;
use crate::xds::{CLUSTER_TYPE, ENDPOINT_TYPE, LISTENER_TYPE};
use prometheus::core::{AtomicU64, GenericGauge};
use tokio::sync::mpsc::error::SendError;

/// AdsClient is a client that can talk to an XDS server using the ADS protocol.
pub(crate) struct AdsClient {
    log: Logger,
    metrics: Metrics,
}

/// Contains the components that handle XDS responses for supported resources.
struct ResourceHandlers {
    cluster_manager: ClusterManager,
    listener_manager: ListenerManager,
}

impl ResourceHandlers {
    // Clear any stale state before (re)connecting.
    pub fn on_reconnect(&mut self) {
        self.cluster_manager.on_reconnect();
    }
}

/// Represents the required arguments to start an rpc session with a server.
struct RpcSessionArgs<'a> {
    log: Logger,
    metrics: Metrics,
    server_addr: String,
    node_id: String,
    resource_handlers: ResourceHandlers,
    backoff: ExponentialBackoff<SystemClock>,
    discovery_req_rx: &'a mut mpsc::Receiver<DiscoveryRequest>,
    shutdown_rx: watch::Receiver<()>,
}

enum RpcSessionError {
    InitialConnect(
        ResourceHandlers,
        ExponentialBackoff<SystemClock>,
        TonicError,
    ),
    Receive(
        ResourceHandlers,
        ExponentialBackoff<SystemClock>,
        tonic::Status,
    ),
    NonRecoverable(&'static str, Box<dyn std::error::Error + Send + Sync>),
}

/// Represents the outcome of an rpc session with a server.
/// We return the resource handlers back so that they can be reused
/// without running into any lifetime issues.
type RpcSessionResult = Result<ResourceHandlers, RpcSessionError>;

/// Represents an error encountered during a client execution.
#[derive(Debug)]
pub enum ExecutionError {
    BackoffLimitExceeded,
    Message(String),
}

/// Represents a full snapshot the all clusters.
pub type ClusterUpdate = HashMap<String, Cluster>;

/// Represents the result of a client execution.
pub type ExecutionResult = Result<(), ExecutionError>;

impl AdsClient {
    pub fn new(base_logger: Logger, metrics_registry: &Registry) -> MetricsResult<Self> {
        let log = base_logger.new(o!("source" => "xds::AdsClient"));
        let metrics = Metrics::new(metrics_registry)?;
        Ok(Self { log, metrics })
    }
    /// Continuously tracks CDS and EDS resources on an ADS server,
    /// sending summarized cluster updates on the provided channel.
    pub async fn run(
        self,
        node_id: String,
        management_servers: Vec<ManagementServer>,
        cluster_updates_tx: mpsc::Sender<ClusterUpdate>,
        listener_manager_args: ListenerManagerArgs,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> ExecutionResult {
        let mut backoff = ExponentialBackoff::<SystemClock>::default();
        let log = self.log;
        let metrics = self.metrics;

        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DiscoveryRequest>(100);
        let cluster_manager =
            ClusterManager::new(log.clone(), cluster_updates_tx, discovery_req_tx.clone());
        let listener_manager =
            ListenerManager::new(log.clone(), listener_manager_args, discovery_req_tx);

        let mut resource_handlers = ResourceHandlers {
            cluster_manager,
            listener_manager,
        };

        // Run the client in a loop.
        // If the connection fails, we retry (with another server if available).
        let mut next_server_index = 0;
        loop {
            // Clear any stale state before (re)connecting.
            resource_handlers.on_reconnect();

            // Pick a server to talk to.
            let server_addr = {
                let server_addr = management_servers
                    .get(next_server_index % management_servers.len())
                    .map(|server| server.address.clone())
                    // We have previously validated that a config provides at least one
                    // server address so this default value shouldn't be necessary.
                    .unwrap_or_else(|| "127.0.0.1:18000".into());
                next_server_index += 1;
                server_addr
            };

            let args = RpcSessionArgs {
                log: log.clone(),
                metrics: metrics.clone(),
                server_addr: server_addr.clone(),
                node_id: node_id.clone(),
                resource_handlers,
                backoff,
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
                        Err(RpcSessionError::InitialConnect(handlers, bk_off, err)) => {
                            resource_handlers = handlers;
                            backoff = bk_off;

                            // Do not retry if this is an invalid URL error that we cannot recover from.
                            if err.to_string().to_lowercase().contains("invalid url") {
                                return Err(ExecutionError::Message(format!("{:?}", err)));
                            }
                            error!(log, "Unable to connect to the XDS server"; "address" => server_addr, "error" => %err);
                            Self::backoff(
                                &log,
                                &mut backoff
                            ).await?;
                        }
                        Err(RpcSessionError::Receive(handlers, bk_off, status)) => {
                            resource_handlers = handlers;
                            backoff = bk_off;
                            error!(log, "Failed to receive from XDS server"; "address" => server_addr, "status" => #?status);
                            Self::backoff(
                                &log,
                                &mut backoff
                            ).await?;
                        }
                    }
                },

                _ = shutdown_rx.changed() => {
                    info!(log, "Stopping client execution - received shutdown signal.");
                    return Ok(())
                },
            }
        }
    }

    /// Executes an RPC session with a server.
    /// A session consists of two concurrent rpc loops executing the XDS protocol
    /// together with a ClusterManager. One loop (receive loop) receives
    /// responses from the server, forwarding them to the ClusterManager
    /// while the other loop (send loop) waits for DiscoveryRequest ACKS/NACKS
    /// from the ClusterManager, forwarding them to the server.
    async fn run_rpc_session(args: RpcSessionArgs<'_>) -> RpcSessionResult {
        let RpcSessionArgs {
            log,
            metrics,
            server_addr,
            node_id,
            resource_handlers,
            backoff,
            discovery_req_rx,
            shutdown_rx,
        } = args;
        let client = match AggregatedDiscoveryServiceClient::connect(server_addr).await {
            Ok(client) => client,
            Err(err) => {
                return Err(RpcSessionError::InitialConnect(
                    resource_handlers,
                    backoff,
                    err,
                ))
            }
        };

        let (mut rpc_tx, rpc_rx) = mpsc::channel::<DiscoveryRequest>(100);

        // Spawn a task that runs the receive loop.
        let mut recv_loop_join_handle = Self::run_receive_loop(
            log.clone(),
            metrics.clone(),
            client,
            rpc_rx,
            resource_handlers,
            backoff,
            shutdown_rx,
        );

        // Fetch the initial set of resources.
        Self::send_initial_cds_and_lds_request(&log, &metrics, node_id, &mut rpc_tx).await?;

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
                    Self::send_discovery_request(&log, &metrics, req, &mut rpc_tx)
                        .await
                        .map_err(|err| RpcSessionError::NonRecoverable(
                            "failed to send discovery request on channel",
                            Box::new(err))
                        )?;
                    } else {
                        info!(log, "Exiting send loop");
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

    #[allow(deprecated)]
    async fn send_initial_cds_and_lds_request(
        log: &Logger,
        metrics: &Metrics,
        node_id: String,
        rpc_tx: &mut mpsc::Sender<DiscoveryRequest>,
    ) -> Result<(), RpcSessionError> {
        for resource_type in &[CLUSTER_TYPE, LISTENER_TYPE] {
            let send_result = Self::send_discovery_request(
                log,
                metrics,
                DiscoveryRequest {
                    version_info: "".into(),
                    node: Some(Node {
                        id: node_id.clone(),
                        cluster: "".into(),
                        metadata: None,
                        dynamic_parameters: Default::default(),
                        locality: None,
                        user_agent_name: "quilkin".into(),
                        extensions: vec![],
                        client_features: vec![],
                        listening_addresses: vec![],
                        user_agent_version_type: None,
                    }),
                    resource_names: vec![], // Wildcard mode.
                    type_url: (*resource_type).into(),
                    response_nonce: "".into(),
                    error_detail: None,
                },
                rpc_tx,
            )
            .await
            .map_err(|err|
                    // An error sending means we have no listener on the other side which
                    // would likely be a bug if we're not already shutting down.
                    RpcSessionError::NonRecoverable(
                        "failed to send initial discovery request for resource on channel",
                        Box::new(err),
                    ));

            if let err @ Err(_) = send_result {
                return err;
            }
        }

        Ok(())
    }

    // Spawns a task that runs a receive loop.
    fn run_receive_loop(
        log: Logger,
        metrics: Metrics,
        mut client: AggregatedDiscoveryServiceClient<TonicChannel>,
        rpc_rx: mpsc::Receiver<DiscoveryRequest>,
        mut resource_handlers: ResourceHandlers,
        mut backoff: ExponentialBackoff<SystemClock>,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> JoinHandle<RpcSessionResult> {
        tokio::spawn(async move {
            let mut response_stream = match client
                .stream_aggregated_resources(Request::new(ReceiverStream::new(rpc_rx)))
                .await
            {
                Ok(response) => response.into_inner(),
                Err(err) => return Err(RpcSessionError::Receive(resource_handlers, backoff, err)),
            };

            // This updates metrics for connection state. It updates the metric to 1 upon
            // creation and back to 0 once it goes out of scope (i.e when the function returns,
            // we are no longer connected since the client must have been dropped as well).
            struct ConnectionState(GenericGauge<AtomicU64>);
            impl ConnectionState {
                fn connected(metric: GenericGauge<AtomicU64>) -> Self {
                    metric.set(1);
                    Self(metric)
                }
            }
            impl Drop for ConnectionState {
                fn drop(&mut self) {
                    self.0.set(0);
                }
            }

            // We are now connected to the server.
            let _connected_state = ConnectionState::connected(metrics.connected_state);

            loop {
                tokio::select! {
                    response = response_stream.message() => {
                        let response = match response {
                            Ok(None) => {
                                // No more messages on the connection.
                                info!(log, "Exiting receive loop - response stream closed.");
                                return Ok(resource_handlers)
                            },
                            Err(err) => return Err(RpcSessionError::Receive(resource_handlers, backoff, err)),
                            Ok(Some(response)) => response
                        };

                        // Reset backoff timer if needed, now that we have
                        // successfully reached the server.
                        backoff.reset();

                        metrics.update_attempt_total.inc();
                        if response.type_url == CLUSTER_TYPE {
                            resource_handlers.cluster_manager.on_cluster_response(response).await;
                        } else if response.type_url == ENDPOINT_TYPE {
                            resource_handlers.cluster_manager.on_cluster_load_assignment_response(response).await;
                        } else if response.type_url == LISTENER_TYPE {
                            resource_handlers.listener_manager.on_listener_response(response).await;
                        } else {
                            metrics.update_failure_total.inc();
                            error!(log, "Unexpected resource"; "type" => response.type_url);
                        }
                    }

                    _ = shutdown_rx.changed() => {
                        info!(log, "Exiting receive loop - received shutdown signal");
                        return Ok(resource_handlers)
                    }
                }
            }
        })
    }

    async fn send_discovery_request(
        log: &Logger,
        metrics: &Metrics,
        req: DiscoveryRequest,
        req_tx: &mut mpsc::Sender<DiscoveryRequest>,
    ) -> Result<(), SendError<DiscoveryRequest>> {
        if req.error_detail.is_some() {
            metrics.update_failure_total.inc();
        } else {
            metrics.update_success_total.inc();
        }
        metrics.requests_total.inc();

        debug!(log, "Sending rpc discovery"; "request" => #?req);

        req_tx.send(req).await
    }

    async fn backoff<C: Clock>(
        log: &Logger,
        backoff: &mut ExponentialBackoff<C>,
    ) -> Result<(), ExecutionError> {
        let delay = backoff
            .next_backoff()
            .ok_or(ExecutionError::BackoffLimitExceeded)?;
        info!(log, "Retrying"; "delay" => #?delay);
        tokio::time::sleep(delay).await;
        Ok(())
    }
}

// Send a Discovery request with the provided arguments on the channel.
pub(super) async fn send_discovery_req(
    log: Logger,
    type_url: &'static str,
    version_info: String,
    response_nonce: String,
    error_message: Option<String>,
    resource_names: Vec<String>,
    discovery_req_tx: &mut mpsc::Sender<DiscoveryRequest>,
) {
    discovery_req_tx
        .send(DiscoveryRequest {
            version_info,
            response_nonce,
            type_url: type_url.into(),
            resource_names,
            node: None,
            error_detail: error_message.map(|message| GrpcStatus {
                code: 2, // 2 is rpc Unknown error
                message,
                details: vec![],
            }),
        })
        .await
        .map_err(|err| {
            warn!(
                log,
                "Failed to send discovery request";
                "type" => %type_url, "error" => %err
            )
        })
        // ok is safe here since an error would mean that we've dropped/closed the receiving
        // side and are no longer sending RPC requests to the server - which only happens
        // when we're shutting down in which case there's nothing we can do here.
        .ok();
}

#[cfg(test)]
mod tests {
    use super::AdsClient;
    use crate::config::ManagementServer;
    use crate::extensions::FilterRegistry;
    use crate::proxy::logger;
    use crate::xds::ads_client::ListenerManagerArgs;
    use crate::xds::envoy::service::discovery::v3::DiscoveryRequest;
    use crate::xds::google::rpc::Status as GrpcStatus;
    use crate::xds::CLUSTER_TYPE;

    use std::time::Duration;

    use prometheus::Registry;
    use tokio::sync::{mpsc, watch};

    #[tokio::test]
    async fn invalid_url() {
        // If we get an invalid URL, we should return immediately rather
        // than backoff or retry.

        let (_shutdown_tx, shutdown_rx) = watch::channel::<()>(());
        let (cluster_updates_tx, _) = mpsc::channel(10);
        let (filter_chain_updates_tx, _) = mpsc::channel(10);
        let run = AdsClient::new(logger(), &Registry::default()).unwrap().run(
            "test-id".into(),
            vec![ManagementServer {
                address: "localhost:18000".into(),
            }],
            cluster_updates_tx,
            ListenerManagerArgs::new(
                Registry::default(),
                FilterRegistry::default(),
                filter_chain_updates_tx,
            ),
            shutdown_rx,
        );

        let execution_result =
            tokio::time::timeout(std::time::Duration::from_millis(100), run).await;
        assert!(execution_result
            .expect("client should bail out immediately")
            .is_err());
    }

    #[tokio::test]
    async fn send_discovery_request() {
        let (mut discovery_req_tx, mut discovery_req_rx) = mpsc::channel(10);

        for error_message in vec![Some("Boo!".into()), None] {
            super::send_discovery_req(
                logger(),
                CLUSTER_TYPE,
                "101".into(),
                "nonce-101".into(),
                error_message.clone(),
                vec!["resource-1".into(), "resource-2".into()],
                &mut discovery_req_tx,
            )
            .await;

            let result = tokio::time::timeout(Duration::from_secs(5), discovery_req_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                DiscoveryRequest {
                    version_info: "101".into(),
                    response_nonce: "nonce-101".into(),
                    type_url: CLUSTER_TYPE.into(),
                    resource_names: vec!["resource-1".into(), "resource-2".into()],
                    node: None,
                    error_detail: error_message.map(|message| GrpcStatus {
                        code: 2,
                        message,
                        details: vec![],
                    }),
                },
                result
            );
        }
    }
}
