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

use std::time::Duration;

use prometheus::Result as MetricsResult;
use rand::Rng;
use tokio::{
    sync::{
        mpsc::{self, error::SendError},
        watch,
    },
    task::JoinHandle,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    transport::{channel::Channel as TonicChannel, Error as TonicError},
    Request,
};
use tryhard::{
    backoff_strategies::{BackoffStrategy, ExponentialBackoff},
    RetryFutureConfig, RetryPolicy,
};

use crate::{
    cluster::SharedCluster,
    config::ManagementServer,
    xds::{
        cluster::ClusterManager,
        envoy::{
            config::core::v3::Node,
            service::discovery::v3::{
                aggregated_discovery_service_client::AggregatedDiscoveryServiceClient,
                DiscoveryRequest, DiscoveryResponse,
            },
        },
        google::rpc::Status as GrpcStatus,
        listener::ListenerManager,
        metrics::Metrics,
        CLUSTER_TYPE, ENDPOINT_TYPE, LISTENER_TYPE,
    },
    Result,
};

/// Use a bounded channel of size 1 on the channels between
///   - the xds listeners and their associated resource manager.
///   - the xds listeners and the xds server.
/// This allows us to fetch updates from the xds server at near the same pace
/// that the proxy is able to apply them (i.e if the channel if full then next time
/// the listener tries to place a new update for the resource manager, we'll block
/// so in that time we don't request more updates from the server)
pub const UPDATES_CHANNEL_BUFFER_SIZE: usize = 1;

/// AdsClient is a client that can talk to an XDS server using the ADS protocol.
pub(crate) struct AdsClient {
    metrics: Metrics,
}

const BACKOFF_INITIAL_DELAY_MILLISECONDS: u64 = 500;
const BACKOFF_MAX_DELAY_SECONDS: u64 = 30;
const BACKOFF_MAX_JITTER_MILLISECONDS: u64 = 2000;

impl AdsClient {
    pub fn new() -> MetricsResult<Self> {
        let metrics = Metrics::new()?;
        Ok(Self { metrics })
    }

    /// Continuously tracks CDS and EDS resources on an ADS server,
    /// sending summarized cluster updates on the provided channel.
    pub async fn run(
        self,
        node_id: String,
        cluster: SharedCluster,
        management_servers: Vec<ManagementServer>,
        filter_chain: crate::filters::SharedFilterChain,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> Result<()> {
        let metrics = self.metrics;

        let mut server_iter = management_servers.iter().cycle();
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(BACKOFF_INITIAL_DELAY_MILLISECONDS));
        let max_delay = Duration::from_secs(BACKOFF_MAX_DELAY_SECONDS);

        let retry_config = RetryFutureConfig::new(u32::MAX).custom_backoff(|attempt, error: &_| {
            // reset after success
            if attempt <= 1 {
                backoff = ExponentialBackoff::new(Duration::from_millis(
                    BACKOFF_INITIAL_DELAY_MILLISECONDS,
                ));
            }

            // max delay + jitter of up to 2 seconds
            let mut delay = backoff.delay(attempt, &error);
            if delay > max_delay {
                delay = max_delay;
            }
            delay += Duration::from_millis(
                rand::thread_rng().gen_range(0..BACKOFF_MAX_JITTER_MILLISECONDS),
            );

            match error {
                RpcSessionError::NonRecoverable(message, error) => {
                    tracing::error!(%message, %error);
                    RetryPolicy::Break
                }

                RpcSessionError::InitialConnect(ref error) => {
                    tracing::error!(%error, "Unable to connect to the XDS server");

                    // Do not retry if this is an invalid URL error that we cannot recover from.
                    // Need to use {:?} as the Display output only returns 'transport error'
                    let err_description = format!("{error:?}");
                    if err_description.to_lowercase().contains("invalid url") {
                        RetryPolicy::Break
                    } else {
                        RetryPolicy::Delay(delay)
                    }
                }

                RpcSessionError::Receive(ref status) => {
                    tracing::error!(status = ?status, "Failed to receive response from XDS server");
                    RetryPolicy::Delay(delay)
                }
            }
        });

        let session_shutdown_rx = shutdown_rx.clone();
        let handle = tryhard::retry_fn(|| {
            let (discovery_req_tx, discovery_req_rx) =
                mpsc::channel::<DiscoveryRequest>(UPDATES_CHANNEL_BUFFER_SIZE);
            let cluster_manager = ClusterManager::new(cluster.clone(), discovery_req_tx.clone());
            let listener_manager = ListenerManager::new(filter_chain.clone(), discovery_req_tx);

            let resource_handlers = ResourceHandlers {
                cluster_manager,
                listener_manager,
            };

            RpcSession {
                discovery_req_rx,
                metrics: metrics.clone(),
                node_id: node_id.clone(),
                // server_iter is guaranteed to always have at least one entry.
                addr: server_iter
                    .next()
                    .map(|server| server.address.to_string())
                    .unwrap(),
                resource_handlers,
                shutdown_rx: session_shutdown_rx.clone(),
            }
            .run()
        })
        .with_config(retry_config);

        tokio::select! {
            result = handle => result.map(drop).map_err(|error| eyre::eyre!(error)),
            _ = shutdown_rx.changed() => {
                tracing::info!("Stopping client execution - received shutdown signal.");
                Ok(())
            },
        }
    }
}

/// Represents the receiving side of the RPC channel.
pub struct RpcReceiver {
    client: AggregatedDiscoveryServiceClient<TonicChannel>,
    metrics: Metrics,
    resource_handlers: ResourceHandlers,
    rpc_rx: mpsc::Receiver<DiscoveryRequest>,
    shutdown_rx: watch::Receiver<()>,
}

impl RpcReceiver {
    /// Spawns the task that runs a receive loop.
    fn run(mut self) -> JoinHandle<Result<(), RpcSessionError>> {
        tokio::spawn(async move {
            let mut response_stream = match self
                .client
                .stream_aggregated_resources(Request::new(ReceiverStream::new(self.rpc_rx)))
                .await
            {
                Ok(response) => response.into_inner(),
                Err(err) => return Err(RpcSessionError::Receive(err)),
            };

            // We are now connected to the server.
            self.metrics.connected_state.set(1);

            let result = loop {
                tokio::select! {
                    response = response_stream.message() => {
                        let response = match response {
                            Ok(None) => {
                                // No more messages on the connection.
                                tracing::info!("Exiting receive loop - response stream closed.");
                                break Ok(())
                            },
                            Err(err) => break Err(RpcSessionError::Receive(err)),
                            Ok(Some(response)) => response
                        };

                        self.metrics.update_attempt_total.inc();
                        if let Err(url) = self.resource_handlers.handle_discovery_response(response).await {
                            self.metrics.update_failure_total.inc();
                            tracing::error!(r#type = %url, "Unexpected resource");
                        }
                    }

                    _ = self.shutdown_rx.changed() => {
                        tracing::info!("Exiting receive loop - received shutdown signal");
                        break Ok(())
                    }
                }
            };

            // We are no longer connected.
            self.metrics.connected_state.set(0);

            result
        })
    }
}

/// Represents a complete aDS gRPC session.
pub struct RpcSession {
    discovery_req_rx: mpsc::Receiver<DiscoveryRequest>,
    metrics: Metrics,
    node_id: String,
    addr: String,
    resource_handlers: ResourceHandlers,
    shutdown_rx: watch::Receiver<()>,
}

impl RpcSession {
    /// Executes an RPC session with a server.
    /// A session consists of two concurrent rpc loops executing the XDS protocol
    /// together with a ClusterManager. One loop (receive loop) receives
    /// responses from the server, forwarding them to the ClusterManager
    /// while the other loop (send loop) waits for DiscoveryRequest ACKS/NACKS
    /// from the ClusterManager, forwarding them to the server.
    async fn run(mut self) -> Result<(), RpcSessionError> {
        let client = match AggregatedDiscoveryServiceClient::connect(self.addr).await {
            Ok(client) => client,
            Err(err) => return Err(RpcSessionError::InitialConnect(err)),
        };

        let (rpc_tx, rpc_rx) = mpsc::channel::<DiscoveryRequest>(UPDATES_CHANNEL_BUFFER_SIZE);

        // Spawn a task that runs the receive loop.
        let mut recv_loop_join_handle = RpcReceiver {
            client,
            metrics: self.metrics.clone(),
            resource_handlers: self.resource_handlers,
            rpc_rx,
            shutdown_rx: self.shutdown_rx,
        }
        .run();

        let sender = RpcSender {
            metrics: self.metrics.clone(),
            rpc_tx,
        };

        // Fetch the initial set of resources.
        sender
            .send_initial_cds_and_lds_request(self.node_id)
            .await?;

        // Run the send loop on the current task.
        loop {
            tokio::select! {
                // Monitor the receive loop task, if it fails then there is
                // no need to remain in the send loop so we exit.
                recv_loop_result = &mut recv_loop_join_handle =>
                    return recv_loop_result.unwrap_or_else(|err|
                        Err(RpcSessionError::NonRecoverable(
                            "receive loop encountered an error", Box::new(err)))),

                req = self.discovery_req_rx.recv() => {
                    if let Some(req) = req {
                    sender.send_discovery_request(req)
                        .await
                        .map_err(|err| RpcSessionError::NonRecoverable(
                            "failed to send discovery request on channel",
                            Box::new(err))
                        )?;
                    } else {
                        tracing::info!("Exiting send loop");
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
}

struct RpcSender {
    metrics: Metrics,
    rpc_tx: mpsc::Sender<DiscoveryRequest>,
}

impl RpcSender {
    async fn send_initial_cds_and_lds_request(
        &self,
        node_id: String,
    ) -> Result<(), RpcSessionError> {
        for resource_type in &[CLUSTER_TYPE, LISTENER_TYPE] {
            let send_result = self
                .send_discovery_request(DiscoveryRequest {
                    node: Some(Node {
                        id: node_id.clone(),
                        user_agent_name: "quilkin".into(),
                        ..Node::default()
                    }),
                    resource_names: vec![], // Wildcard mode.
                    type_url: (*resource_type).into(),
                    ..DiscoveryRequest::default()
                })
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

    async fn send_discovery_request(
        &self,
        req: DiscoveryRequest,
    ) -> Result<(), SendError<DiscoveryRequest>> {
        if req.error_detail.is_some() {
            self.metrics.update_failure_total.inc();
        } else {
            self.metrics.update_success_total.inc();
        }

        self.metrics.requests_total.inc();

        tracing::debug!(request = ?req, "Sending rpc discovery");

        self.rpc_tx.send(req).await
    }
}

/// Contains the components that handle xDS responses for supported resources.
struct ResourceHandlers {
    cluster_manager: ClusterManager,
    listener_manager: ListenerManager,
}

impl ResourceHandlers {
    /// Checks if the discovery response matches any well known types, if none
    /// match then it will return an `Err` containing the URL of the type
    /// not recognised.
    async fn handle_discovery_response(
        &mut self,
        response: DiscoveryResponse,
    ) -> Result<(), String> {
        match &*response.type_url {
            CLUSTER_TYPE => self.cluster_manager.on_cluster_response(response).await,
            ENDPOINT_TYPE => {
                self.cluster_manager
                    .on_cluster_load_assignment_response(response)
                    .await
            }
            LISTENER_TYPE => self.listener_manager.on_listener_response(response).await,
            _ => return Err(response.type_url),
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum RpcSessionError {
    #[error("Failed to establish initial connection.\n {0:?}")]
    InitialConnect(TonicError),

    #[error("Error occured while receiving data. Status: {0}")]
    Receive(tonic::Status),

    #[error("Non-recoverable aDS error:\nname: {0}\n{1}")]
    NonRecoverable(&'static str, Box<dyn std::error::Error + Send + Sync>),
}

// Send a Discovery request with the provided arguments on the channel.
pub(super) async fn send_discovery_req(
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
        .map_err(|error| {
            tracing::warn!(
                r#type = %type_url,
                %error,
                "Failed to send discovery request"
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
    use crate::xds::envoy::service::discovery::v3::DiscoveryRequest;
    use crate::xds::google::rpc::Status as GrpcStatus;
    use crate::xds::CLUSTER_TYPE;

    use std::time::Duration;

    use tokio::sync::{mpsc, watch};

    #[tokio::test]
    /// If we get an invalid URL, we should return immediately rather
    /// than backoff or retry.
    async fn invalid_url() {
        let filter_chain = crate::filters::SharedFilterChain::empty();
        let cluster = crate::cluster::SharedCluster::empty().unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel::<()>(());
        let run = AdsClient::new().unwrap().run(
            "test-id".into(),
            cluster,
            vec![ManagementServer {
                address: "localhost:18000".into(),
            }],
            filter_chain,
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
