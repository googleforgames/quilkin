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

use std::{sync::Arc, time::Duration};

use rand::Rng;
use tokio::sync::mpsc::{self, error::SendError};
use tonic::{
    transport::{channel::Channel as TonicChannel, Error as TonicError},
};
use tryhard::{
    backoff_strategies::{BackoffStrategy, ExponentialBackoff},
    RetryFutureConfig, RetryPolicy,
};

use crate::{
    config::Config,
    xds::{
        cluster::ClusterManager,
        config::core::v3::Node,
        google::rpc::Status as GrpcStatus,
        listener::ListenerManager,
        metrics::Metrics,
        service::discovery::v3::{
            aggregated_discovery_service_client::AggregatedDiscoveryServiceClient,
            DiscoveryRequest
        },
        Resource, ResourceType,
    },
    Result,
};

/// Client that can talk to an XDS server using the aDS protocol.
#[derive(Clone)]
pub struct Client {
    client: AggregatedDiscoveryServiceClient<TonicChannel>,
    config: Arc<Config>,
    metrics: Metrics,
}

impl Client {
    pub async fn connect(config: Arc<Config>) -> Result<Self> {
        const BACKOFF_INITIAL_DELAY_MILLISECONDS: u64 = 500;
        const BACKOFF_MAX_DELAY_SECONDS: u64 = 30;
        const BACKOFF_MAX_JITTER_MILLISECONDS: u64 = 2000;

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
                    tracing::error!(?error, "Unable to connect to the XDS server");

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

        let management_servers = config.management_servers.load();
        let mut addresses = management_servers.iter().cycle().map(|server| server.address.clone());
        let connect_to_server = tryhard::retry_fn(|| {
            let address = addresses.next();
            async {
                match address {
                    None => Err(RpcSessionError::Receive(tonic::Status::internal(
                        "Failed initial connection",
                    ))),
                    Some(endpoint) => AggregatedDiscoveryServiceClient::connect(endpoint)
                        .await
                        .map_err(RpcSessionError::InitialConnect),
                }
            }
        })
        .with_config(retry_config);

        let client = connect_to_server.await;

        Ok(Self {
            client: client?,
            config,
            metrics: Metrics::new()?,
        })
    }

    /// Starts a new stream to the xDS management server.
    pub async fn stream(&self) -> Result<Stream> {
        Stream::connect(self.clone()).await
    }
}

/// An active xDS gRPC management stream.
pub struct Stream {
    metrics: Metrics,
    config: Arc<Config>,
    requests: tokio::sync::mpsc::Sender<DiscoveryRequest>,
    responses: tokio::task::JoinHandle<Result<()>>,
}

impl Stream {
    async fn connect(
        xds: Client,
    ) -> Result<Self> {
        let (requests, rx) = tokio::sync::mpsc::channel(1);
        // Cloning tonic clients is cheap and encouraged.
        let Client { mut client, metrics, config } = xds;
        let responses = tokio::spawn({
            let metrics = metrics.clone();
            let requests = requests.clone();
            let config = config.clone();
            async move {
                let mut responses = client
                    .stream_aggregated_resources(tokio_stream::wrappers::ReceiverStream::from(rx))
                    .await?
                    .into_inner();

                // We are now connected to the server.
                metrics.connected_state.set(1);

                while let Some(response) = responses.message().await? {
                    metrics.requests_total.inc();

                    let resources = response.resources.iter().cloned().map(Resource::try_from).collect::<Result<Vec<_>, _>>()?;
                    let mut request = DiscoveryRequest::try_from(response)?;
                    if let Err(error) = resources.iter().map(|resource| config.apply(resource)).collect::<Result<(), _>>() {
                        metrics.update_failure_total.inc();
                        request.error_detail = Some(crate::xds::google::rpc::Status {
                            code: 3,
                            message: error.to_string(),
                            ..<_>::default()
                        });
                    } else {
                        metrics.update_success_total.inc();
                    }

                    requests.send(request).await?;
                }

                Ok(())
            }
        });

        Ok(Self {
            config,
            metrics,
            requests,
            responses,
        })
    }

    pub async fn send(&mut self, resource_type: ResourceType, names: &[String]) -> Result<()> {
        let request = DiscoveryRequest {
            node: Some(Node {
                id: self.config.proxy.id.clone(),
                user_agent_name: "quilkin".into(),
                ..Node::default()
            }),
            resource_names: names.to_vec(),
            type_url: resource_type.type_url().into(),
            ..DiscoveryRequest::default()
        };

        tokio::select! {
            result = &mut self.responses => {
                result??;
            }
            result = self.requests.send(request) => {
                result?;
            }
        }

        Ok(())
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // We are no longer connected.
        self.metrics.connected_state.set(0);
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
    use super::*;
    use crate::config::ManagementServer;
    use crate::xds::{
        google::rpc::Status as GrpcStatus, service::discovery::v3::DiscoveryRequest, ResourceType,
    };

    use std::{net::Ipv4Addr, time::Duration};

    use tokio::sync::{mpsc, watch};

    const CLUSTER_TYPE: &'static str = ResourceType::Cluster.type_url();

    #[tokio::test]
    /// If we get an invalid URL, we should return immediately rather
    /// than backoff or retry.
    async fn invalid_url() {
        let filter_chain = crate::filters::SharedFilterChain::empty();
        let cluster = crate::cluster::SharedCluster::empty().unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel::<()>(());
        let config = crate::Config::builder()
            .management_servers(["localhost:18000".into()])
            .build()
            .unwrap();
        let run = Client::connect(Arc::new(config));

        let execution_result =
            tokio::time::timeout(std::time::Duration::from_millis(10000), run).await;
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
