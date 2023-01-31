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

use std::{collections::HashSet, sync::Arc, time::Duration};

use futures::StreamExt;
use rand::Rng;
use tokio::sync::{broadcast, Mutex};
use tonic::transport::{channel::Channel as TonicChannel, Endpoint, Error as TonicError};
use tracing::Instrument;
use tryhard::{
    backoff_strategies::{BackoffStrategy, ExponentialBackoff},
    RetryFutureConfig, RetryPolicy,
};

use crate::{
    xds::{
        config::core::v3::Node,
        metrics,
        service::discovery::v3::{
            aggregated_discovery_service_client::AggregatedDiscoveryServiceClient, DiscoveryRequest,
        },
        Resource, ResourceType,
    },
    Result,
};

type AdsClient = AggregatedDiscoveryServiceClient<TonicChannel>;

/// Client that can talk to an XDS server using the aDS protocol.
#[derive(Clone)]
pub struct Client {
    identifier: String,
    management_servers: Vec<Endpoint>,
    client: AdsClient,
}

impl Client {
    #[tracing::instrument(skip_all, level = "trace", fields(servers = ?management_servers))]
    pub async fn connect(identifier: String, management_servers: Vec<Endpoint>) -> Result<Self> {
        let client = Self::new_ads_client(&management_servers).await?;
        Ok(Self {
            client,
            identifier,
            management_servers,
        })
    }

    async fn new_ads_client(management_servers: &[Endpoint]) -> Result<AdsClient> {
        use crate::config::{
            BACKOFF_INITIAL_DELAY_MILLISECONDS, BACKOFF_MAX_DELAY_SECONDS,
            BACKOFF_MAX_JITTER_MILLISECONDS, CONNECTION_TIMEOUT,
        };

        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(BACKOFF_INITIAL_DELAY_MILLISECONDS));
        let max_delay = Duration::from_secs(BACKOFF_MAX_DELAY_SECONDS);

        let retry_config = RetryFutureConfig::new(u32::MAX).custom_backoff(|attempt, error: &_| {
            tracing::info!(attempt, "Retrying to connect");
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
                RpcSessionError::InvalidEndpoint(ref error) => {
                    tracing::error!(?error, "Error creating endpoint");
                    // Do not retry if this is an invalid URL error that we cannot recover from.
                    RetryPolicy::Break
                }
                RpcSessionError::InitialConnect(ref error) => {
                    tracing::warn!(?error, "Unable to connect to the XDS server");
                    RetryPolicy::Delay(delay)
                }
                RpcSessionError::Receive(ref status) => {
                    tracing::warn!(status = ?status, "Failed to receive response from XDS server");
                    RetryPolicy::Delay(delay)
                }
            }
        });

        let mut addresses = management_servers.iter().cycle();
        let connect_to_server = tryhard::retry_fn(|| {
            let address = addresses.next();
            async move {
                match address {
                    None => Err(RpcSessionError::Receive(tonic::Status::internal(
                        "Failed initial connection",
                    ))),
                    Some(endpoint) => {
                        let endpoint = endpoint
                            .clone()
                            .connect_timeout(Duration::from_secs(CONNECTION_TIMEOUT));

                        // make sure that we have everything we will need in our URI
                        if endpoint.uri().scheme().is_none() {
                            return Err(RpcSessionError::InvalidEndpoint(
                                "No scheme provided".into(),
                            ));
                        } else if endpoint.uri().host().is_none() {
                            return Err(RpcSessionError::InvalidEndpoint(
                                "No host provided".into(),
                            ));
                        }

                        AggregatedDiscoveryServiceClient::connect(endpoint)
                            .instrument(tracing::debug_span!(
                                "AggregatedDiscoveryServiceClient::connect"
                            ))
                            .await
                            .map_err(RpcSessionError::InitialConnect)
                    }
                }
            }
        })
        .with_config(retry_config);

        let client = connect_to_server
            .instrument(tracing::trace_span!("xds_client_connect"))
            .await?;
        tracing::info!("Connected to xDS server");
        Ok(client)
    }

    /// Starts a new stream to the xDS management server.
    pub async fn stream(
        &self,
        on_new_resource: impl Fn(&Resource) -> crate::Result<()> + Send + Sync + 'static,
    ) -> Result<Stream> {
        Stream::connect(self, on_new_resource).await
    }
}

type SubscribedResources = Arc<Mutex<HashSet<(ResourceType, Vec<String>)>>>;

/// An active xDS gRPC management stream.
pub struct Stream {
    identifier: Arc<str>,
    requests: broadcast::Sender<DiscoveryRequest>,
    handle_discovery_response: tokio::task::JoinHandle<Result<()>>,
    subscribed_resources: SubscribedResources,
}

impl Stream {
    #[tracing::instrument(level = "trace", skip_all)]
    async fn connect(
        Client {
            client,
            identifier,
            management_servers,
        }: &Client,
        on_new_resource: impl Fn(&Resource) -> crate::Result<()> + Send + Sync + 'static,
    ) -> Result<Self> {
        let (requests, mut rx) = broadcast::channel(12);
        let subscribed_resources: SubscribedResources = <_>::default();
        let identifier: Arc<str> = Arc::from(&**identifier);

        let handle_discovery_response = tokio::spawn({
            let mut client = client.clone();
            let identifier = identifier.clone();
            let mut requests = requests.clone();
            let management_servers = management_servers.clone();
            let subscribed_resources = subscribed_resources.clone();
            async move {
                loop {
                    let mut responses = client
                        .stream_aggregated_resources(
                            tokio_stream::wrappers::BroadcastStream::from(rx)
                                // Errors only happen if the stream is behind, which
                                // we don't care about, we only want the latest
                                // state of the world.
                                .filter_map(|result| futures::future::ready(result.ok())),
                        )
                        .in_current_span()
                        .await?
                        .into_inner();

                    loop {
                        let timeout = tokio::time::sleep(std::time::Duration::from_millis(500));
                        let new_message = responses.message();

                        tokio::select! {
                            _ = timeout => {
                                Self::refresh_resources(&identifier, &subscribed_resources, &mut requests).await?;
                            }
                            response = new_message => {
                                let Some(response) = response.map_err(|error| tracing::warn!(%error, "Error from xDS server")).ok().flatten() else {
                                    break;
                                };

                                let identifier = response
                                    .control_plane
                                    .as_ref()
                                    .map(|cp| cp.identifier.clone())
                                    .unwrap_or_default();
                                let _stream_metrics =
                                    super::metrics::StreamConnectionMetrics::new(&identifier);
                                tracing::info!(
                                    id = &*response.version_info,
                                    r#type = &*response.type_url,
                                    nonce = &*response.nonce,
                                    control_plane = &*identifier,
                                    "Received response"
                                );

                                let result = response
                                    .resources
                                    .iter()
                                    .cloned()
                                    .map(Resource::try_from)
                                    .try_for_each(|resource| {
                                        let resource = resource?;
                                        metrics::DISCOVERY_RESPONSES
                                            .with_label_values(&[&*identifier, resource.type_url()])
                                            .inc();
                                        (on_new_resource)(&resource)
                                    });

                                let mut request = DiscoveryRequest::try_from(response)?;
                                if let Err(error) = result {
                                    metrics::NACKS
                                        .with_label_values(&[&*identifier, &*request.type_url])
                                        .inc();
                                    request.error_detail = Some(crate::xds::google::rpc::Status {
                                        code: 3,
                                        message: error.to_string(),
                                        ..<_>::default()
                                    });
                                } else {
                                    metrics::ACKS
                                        .with_label_values(&[&*identifier, &*request.type_url])
                                        .inc();
                                }

                                requests.send(request)?;
                            }
                            else => {
                                break;
                            }
                        }
                    }

                    tracing::info!("Lost connection to xDS, retrying");
                    // If we've reached here, something has gone wrong with the
                    // connection, so we just create a new client and restart.
                    client = Client::new_ads_client(&management_servers).await?;
                    rx = requests.subscribe();
                    Self::refresh_resources(&identifier, &subscribed_resources, &mut requests).await?;
                }
            }
            .instrument(tracing::trace_span!("handle_discovery_response"))
        });

        Ok(Self {
            identifier,
            requests,
            handle_discovery_response,
            subscribed_resources,
        })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn send(&mut self, resource_type: ResourceType, names: &[String]) -> Result<()> {
        self.subscribed_resources
            .lock()
            .await
            .insert((resource_type, names.to_vec()));
        Self::send_without_cache(&self.identifier, &mut self.requests, resource_type, names)
    }

    async fn refresh_resources(
        identifier: &str,
        subscribed_resources: &SubscribedResources,
        requests: &mut broadcast::Sender<DiscoveryRequest>,
    ) -> Result<()> {
        for (resource, names) in subscribed_resources.lock().await.iter() {
            Self::send_without_cache(identifier, requests, *resource, names)?;
        }

        Ok(())
    }

    fn send_without_cache(
        identifier: &str,
        requests: &mut broadcast::Sender<DiscoveryRequest>,
        resource_type: ResourceType,
        names: &[String],
    ) -> Result<()> {
        let request = DiscoveryRequest {
            node: Some(Node {
                id: identifier.into(),
                user_agent_name: "quilkin".into(),
                ..Node::default()
            }),
            resource_names: names.to_vec(),
            type_url: resource_type.type_url().into(),
            ..DiscoveryRequest::default()
        };

        tracing::trace!(r#type=%resource_type, ?names, "sending discovery request");
        requests.send(request).map_err(From::from).map(drop)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.handle_discovery_response.abort();
    }
}

#[derive(Debug, thiserror::Error)]
enum RpcSessionError {
    #[error("Invalid endpoint. \n {0}")]
    InvalidEndpoint(String),

    #[error("Failed to establish initial connection.\n {0:?}")]
    InitialConnect(TonicError),

    #[error("Error occurred while receiving data. Status: {0}")]
    Receive(tonic::Status),
}
