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

use std::{collections::HashSet, sync::atomic::Ordering, sync::Arc, time::Duration};

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
    cli::Admin,
    config::Config,
    net::xds::{
        config::core::v3::Node,
        relay::aggregated_control_plane_discovery_service_client::AggregatedControlPlaneDiscoveryServiceClient,
        service::discovery::v3::{
            aggregated_discovery_service_client::AggregatedDiscoveryServiceClient,
            DiscoveryRequest, DiscoveryResponse,
        },
        Resource, ResourceType,
    },
    Result,
};

type AdsGrpcClient = AggregatedDiscoveryServiceClient<TonicChannel>;
type MdsGrpcClient = AggregatedControlPlaneDiscoveryServiceClient<TonicChannel>;
type SubscribedResources = Arc<Mutex<HashSet<(ResourceType, Vec<String>)>>>;

pub type AdsClient = Client<AdsGrpcClient>;
pub type AdsStream = BidirectionalStream<AdsGrpcClient>;
pub type MdsClient = Client<MdsGrpcClient>;
pub type MdsStream = BidirectionalStream<MdsGrpcClient>;

#[tonic::async_trait]
pub trait ServiceClient: Clone + Sized + Send + 'static {
    type Request: Clone + Send + Sync + Sized + 'static + std::fmt::Debug;
    type Response: Clone + Send + Sync + Sized + 'static + std::fmt::Debug;

    async fn connect(endpoint: tonic::transport::Endpoint)
        -> Result<Self, tonic::transport::Error>;
    async fn stream_requests<S: tonic::IntoStreamingRequest<Message = Self::Request> + Send>(
        &mut self,
        stream: S,
    ) -> tonic::Result<tonic::Response<tonic::Streaming<Self::Response>>>;
}

#[tonic::async_trait]
impl ServiceClient for AdsGrpcClient {
    type Request = DiscoveryRequest;
    type Response = DiscoveryResponse;

    async fn connect(
        endpoint: tonic::transport::Endpoint,
    ) -> Result<Self, tonic::transport::Error> {
        Ok(AdsGrpcClient::connect(endpoint)
            .await?
            .max_decoding_message_size(crate::config::max_grpc_message_size())
            .max_encoding_message_size(crate::config::max_grpc_message_size()))
    }

    async fn stream_requests<S: tonic::IntoStreamingRequest<Message = Self::Request> + Send>(
        &mut self,
        stream: S,
    ) -> tonic::Result<tonic::Response<tonic::Streaming<Self::Response>>> {
        self.stream_aggregated_resources(stream).await
    }
}

#[tonic::async_trait]
impl ServiceClient for MdsGrpcClient {
    type Request = DiscoveryResponse;
    type Response = DiscoveryRequest;

    async fn connect(
        endpoint: tonic::transport::Endpoint,
    ) -> Result<Self, tonic::transport::Error> {
        Ok(MdsGrpcClient::connect(endpoint)
            .await?
            .max_decoding_message_size(crate::config::max_grpc_message_size())
            .max_encoding_message_size(crate::config::max_grpc_message_size()))
    }

    async fn stream_requests<S: tonic::IntoStreamingRequest<Message = Self::Request> + Send>(
        &mut self,
        stream: S,
    ) -> tonic::Result<tonic::Response<tonic::Streaming<Self::Response>>> {
        self.stream_aggregated_resources(stream).await
    }
}

/// Client that can talk to an XDS server using the aDS protocol.
#[derive(Clone)]
pub struct Client<C: ServiceClient> {
    client: C,
    identifier: Arc<str>,
    management_servers: Vec<Endpoint>,
    mode: Admin,
}

impl<C: ServiceClient> Client<C> {
    #[tracing::instrument(skip_all, level = "trace", fields(servers = ?management_servers))]
    pub async fn connect(
        identifier: String,
        mode: Admin,
        management_servers: Vec<Endpoint>,
    ) -> Result<Self> {
        let client = Self::connect_with_backoff(&management_servers).await?;
        Ok(Self {
            client,
            identifier: Arc::from(identifier),
            management_servers,
            mode,
        })
    }

    async fn connect_with_backoff(management_servers: &[Endpoint]) -> Result<C> {
        use crate::config::{
            BACKOFF_INITIAL_DELAY_MILLISECONDS, BACKOFF_MAX_DELAY_SECONDS,
            BACKOFF_MAX_JITTER_MILLISECONDS, CONNECTION_TIMEOUT,
        };

        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(BACKOFF_INITIAL_DELAY_MILLISECONDS));
        let max_delay = Duration::from_secs(BACKOFF_MAX_DELAY_SECONDS);

        let retry_config = RetryFutureConfig::new(u32::MAX).custom_backoff(|attempt, error: &_| {
            tracing::info!(attempt, "retrying to connect");
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
                    tracing::error!(?error, "error creating endpoint");
                    // Do not retry if this is an invalid URL error that we cannot recover from.
                    RetryPolicy::Break
                }
                RpcSessionError::InitialConnect(ref error) => {
                    tracing::warn!(?error, "unable to connect to the xDS server");
                    RetryPolicy::Delay(delay)
                }
                RpcSessionError::Receive(ref status) => {
                    tracing::warn!(status = ?status, "failed to receive response from xDS server");
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
                        tracing::info!("attempting to connect to `{}`", endpoint.uri());
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

                        C::connect(endpoint)
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
            .instrument(tracing::trace_span!("client_connect"))
            .await?;
        tracing::info!("connected to management server");
        Ok(client)
    }
}

impl MdsClient {
    pub fn mds_client_stream(&self, config: Arc<Config>) -> MdsStream {
        MdsStream::mds_client_stream(self, config)
    }
}

impl AdsClient {
    /// Starts a new stream to the xDS management server.
    pub fn xds_client_stream(
        &self,
        config: Arc<Config>,
        idle_request_interval_secs: u64,
    ) -> AdsStream {
        AdsStream::xds_client_stream(self, config, idle_request_interval_secs)
    }
}

/// An active xDS gRPC management stream.
pub struct BidirectionalStream<C: ServiceClient> {
    identifier: Arc<str>,
    requests: broadcast::Sender<C::Request>,
    handle_discovery_response: tokio::task::JoinHandle<Result<()>>,
    subscribed_resources: SubscribedResources,
}

impl AdsStream {
    pub fn xds_client_stream(
        Client {
            client,
            identifier,
            management_servers,
            mode,
        }: &AdsClient,
        config: Arc<Config>,
        idle_request_interval_secs: u64,
    ) -> Self {
        let mut client = client.clone();
        let identifier = identifier.clone();
        let management_servers = management_servers.clone();
        let mode = mode.clone();
        Self::connect(
            identifier.clone(),
            move |(mut requests, mut rx), subscribed_resources| async move {
                tracing::trace!("starting xDS client stream task");
                loop {
                    let config = config.clone();
                    tracing::trace!("connecting to grpc stream");
                    let result = client
                        .stream_requests(
                            // Errors only happen if the stream is behind, which
                            // we don't care about, we only want the latest
                            // state of the world.
                            tokio_stream::wrappers::BroadcastStream::from(rx)
                                .filter_map(|result| futures::future::ready(result.ok())),
                        )
                        .in_current_span()
                        .await
                        .map(|streaming| streaming.into_inner());

                    let stream = match result {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::warn!(%error, "stream broken");
                            client = AdsClient::connect_with_backoff(&management_servers).await?;
                            rx = requests.subscribe();
                            Self::refresh_resources(
                                &identifier,
                                &subscribed_resources,
                                &mut requests,
                            )
                            .await?;
                            continue;
                        }
                    };

                    tracing::trace!("creating discovery response handler");
                    let mut stream = handle_discovery_responses(
                        (&*identifier).into(),
                        stream,
                        move |resource| config.apply(resource),
                    );
                    let runtime_config = mode.unwrap_proxy();

                    loop {
                        let next_response = tokio::time::timeout(
                            std::time::Duration::from_secs(idle_request_interval_secs),
                            stream.next(),
                        );

                        match next_response.await {
                            Ok(Some(Ok(ack))) => {
                                runtime_config
                                    .xds_is_healthy
                                    .read()
                                    .as_deref()
                                    .unwrap()
                                    .store(true, Ordering::SeqCst);

                                tracing::trace!("received ack");
                                requests.send(ack)?;
                                continue;
                            }
                            Ok(Some(Err(error))) => {
                                tracing::warn!(%error, "xDS stream error");
                                break;
                            }
                            Ok(None) => {
                                tracing::warn!("xDS stream terminated");
                                break;
                            }
                            Err(_) => {
                                tracing::info!(
                                    "exceeded idle request interval sending new requests"
                                );
                                Self::refresh_resources(
                                    &identifier,
                                    &subscribed_resources,
                                    &mut requests,
                                )
                                .await?;
                            }
                        }
                    }

                    runtime_config
                        .xds_is_healthy
                        .read()
                        .as_deref()
                        .unwrap()
                        .store(false, Ordering::SeqCst);

                    tracing::info!("Lost connection to xDS, retrying");
                    client = AdsClient::connect_with_backoff(&management_servers).await?;
                    rx = requests.subscribe();
                    Self::refresh_resources(&identifier, &subscribed_resources, &mut requests)
                        .await?;
                }
            },
        )
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub async fn discovery_request(
        &mut self,
        resource_type: ResourceType,
        names: &[String],
    ) -> Result<()> {
        self.subscribed_resources
            .lock()
            .await
            .insert((resource_type, names.to_vec()));
        Self::discovery_request_without_cache(
            &self.identifier,
            &mut self.requests,
            resource_type,
            names,
        )
    }
}

impl MdsStream {
    pub fn mds_client_stream(
        Client {
            client,
            identifier,
            management_servers,
            mode,
        }: &MdsClient,
        config: Arc<Config>,
    ) -> Self {
        let mut client = client.clone();
        let identifier = identifier.clone();
        let management_servers = management_servers.clone();
        let mode = mode.clone();
        Self::connect(
            identifier.clone(),
            move |(requests, mut rx), _| async move {
                tracing::trace!("starting relay client stream task");
                loop {
                    let initial_response = DiscoveryResponse {
                        control_plane: Some(crate::net::xds::config::core::v3::ControlPlane {
                            identifier: (&*identifier).into(),
                        }),
                        ..<_>::default()
                    };
                    tracing::trace!("sending request");
                    let _ = requests.send(initial_response);
                    tracing::trace!("streaming requests");
                    let stream = client
                        .stream_requests(
                            // Errors only happen if the stream is behind, which
                            // we don't care about, we only want the latest
                            // state of the world.
                            tokio_stream::wrappers::BroadcastStream::from(rx)
                                .filter_map(|result| futures::future::ready(result.ok())),
                        )
                        .in_current_span()
                        .await?
                        .into_inner();
                    tracing::trace!("control plane: creating from config");
                    let control_plane = super::server::ControlPlane::from_arc(
                        config.clone(),
                        mode.idle_request_interval_secs(),
                    );
                    tracing::trace!("control plane: streaming aggregated resources");

                    let timeout = tokio::time::timeout(
                        std::time::Duration::from_secs(mode.idle_request_interval_secs()),
                        control_plane.stream_aggregated_resources(stream),
                    );

                    let mut stream = match timeout.await {
                        Ok(result) => result?,
                        _ => {
                            tracing::warn!("initial connection to relay server failed, retrying");
                            client = MdsClient::connect_with_backoff(&management_servers)
                                .await
                                .unwrap();
                            rx = requests.subscribe();
                            continue;
                        }
                    };

                    tracing::trace!("relay marked as healthy");
                    mode.unwrap_agent()
                        .relay_is_healthy
                        .store(true, Ordering::SeqCst);

                    loop {
                        let timeout = tokio::time::timeout(
                            std::time::Duration::from_secs(mode.idle_request_interval_secs()),
                            stream.next(),
                        );

                        match timeout.await {
                            Ok(Some(result)) => {
                                let response = result?;
                                tracing::debug!(config=%serde_json::to_value(&config).unwrap(), "received discovery response");
                                requests.send(response)?;
                            }
                            _ => break,
                        }
                    }

                    mode.unwrap_agent()
                        .relay_is_healthy
                        .store(false, Ordering::SeqCst);

                    tracing::warn!("lost connection to relay server, retrying");
                    client = MdsClient::connect_with_backoff(&management_servers)
                        .await
                        .unwrap();
                    rx = requests.subscribe();
                }
            },
        )
    }
}

impl<C: ServiceClient> BidirectionalStream<C> {
    pub fn connect<F>(
        identifier: Arc<str>,
        response_task: impl FnOnce(
            (
                broadcast::Sender<C::Request>,
                broadcast::Receiver<C::Request>,
            ),
            SubscribedResources,
        ) -> F,
    ) -> Self
    where
        F: std::future::Future<Output = crate::Result<()>> + Send + 'static,
    {
        let (requests, rx) = broadcast::channel::<C::Request>(12);
        let subscribed_resources: SubscribedResources = <_>::default();

        tracing::trace!("spawning stream background task");
        let handle_discovery_response = tokio::spawn({
            let requests = requests.clone();
            let subscribed_resources = subscribed_resources.clone();
            (response_task)((requests, rx), subscribed_resources)
                .instrument(tracing::trace_span!("handle_discovery_response"))
        });

        Self {
            identifier,
            requests,
            handle_discovery_response,
            subscribed_resources,
        }
    }

    pub(crate) fn requests(&self) -> broadcast::Sender<C::Request> {
        self.requests.clone()
    }

    async fn refresh_resources(
        identifier: &str,
        subscribed_resources: &SubscribedResources,
        requests: &mut broadcast::Sender<DiscoveryRequest>,
    ) -> Result<()> {
        for (resource, names) in subscribed_resources.lock().await.iter() {
            Self::discovery_request_without_cache(identifier, requests, *resource, names)?;
        }

        Ok(())
    }

    pub(crate) fn discovery_request_without_cache(
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

impl<C: ServiceClient> Drop for BidirectionalStream<C> {
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

pub fn handle_discovery_responses(
    identifier: String,
    stream: impl futures::Stream<Item = tonic::Result<DiscoveryResponse>> + 'static + Send,
    on_new_resource: impl Fn(&Resource) -> crate::Result<()> + Send + Sync + 'static,
) -> std::pin::Pin<Box<dyn futures::Stream<Item = Result<DiscoveryRequest>> + Send>> {
    Box::pin(async_stream::try_stream! {
        let _stream_metrics = super::metrics::StreamConnectionMetrics::new(identifier.clone());
        tracing::debug!("awaiting response");
        for await response in stream
        {
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(%error, "Error from xDS server");
                    break;
                }
            };

            let control_plane_identifier = response.control_plane.as_ref().map(|cp| cp.identifier.clone()).unwrap_or_default();

            super::metrics::discovery_responses(&control_plane_identifier, &response.type_url).inc();
            tracing::debug!(
                version = &*response.version_info,
                r#type = &*response.type_url,
                nonce = &*response.nonce,
                "received response"
            );

            let mut resource_names = Vec::with_capacity(response.resources.len());
            let result = response
                .resources
                .into_iter()
                .map(Resource::try_from)
                .try_for_each(|resource| {
                    let resource = resource?;
                    resource_names.push(resource.name().to_owned());

                    tracing::debug!("applying resource");
                    (on_new_resource)(&resource)
                });

            let error_detail = if let Err(error) = result {
                super::metrics::nacks(&control_plane_identifier, &response.type_url).inc();
                Some(crate::net::xds::google::rpc::Status {
                    code: 3,
                    message: error.to_string(),
                    ..Default::default()
                })
            } else {
                super::metrics::acks(&control_plane_identifier, &response.type_url).inc();
                None
            };

            let request = DiscoveryRequest {
                resource_names,
                version_info: response.version_info,
                type_url: response.type_url,
                response_nonce: response.nonce,
                error_detail,
                ..Default::default()
            };
            yield request;
        }
    })
}
