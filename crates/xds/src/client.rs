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

use std::{
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
};

use futures::StreamExt;
use rand::Rng;
use tonic::transport::{channel::Channel as TonicChannel, Endpoint, Error as TonicError};
use tracing::Instrument;
use tryhard::{
    backoff_strategies::{BackoffStrategy, ExponentialBackoff},
    RetryFutureConfig, RetryPolicy,
};

use crate::{
    generated::{
        envoy::{
            config::core::v3::Node,
            service::discovery::v3::{
                aggregated_discovery_service_client::AggregatedDiscoveryServiceClient,
                DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
            },
        },
        quilkin::relay::v1alpha1::aggregated_control_plane_discovery_service_client::AggregatedControlPlaneDiscoveryServiceClient,
    },
    resource::{Resource, ResourceType},
    Result,
};

type AdsGrpcClient = AggregatedDiscoveryServiceClient<TonicChannel>;
type MdsGrpcClient = AggregatedControlPlaneDiscoveryServiceClient<TonicChannel>;

pub type AdsClient = Client<AdsGrpcClient>;
pub type MdsClient = Client<MdsGrpcClient>;

pub(crate) const IDLE_REQUEST_INTERVAL: Duration = Duration::from_secs(30);

#[tonic::async_trait]
pub trait ServiceClient: Clone + Sized + Send + 'static {
    type Request: Clone + Send + Sync + Sized + 'static + std::fmt::Debug;
    type Response: Clone + Send + Sync + Sized + 'static + std::fmt::Debug;

    async fn connect_to_endpoint(
        endpoint: tonic::transport::Endpoint,
    ) -> Result<Self, tonic::transport::Error>;
    async fn stream_requests<S: tonic::IntoStreamingRequest<Message = Self::Request> + Send>(
        &mut self,
        stream: S,
    ) -> tonic::Result<tonic::Response<tonic::Streaming<Self::Response>>>;
}

#[tonic::async_trait]
impl ServiceClient for AdsGrpcClient {
    type Request = DiscoveryRequest;
    type Response = DiscoveryResponse;

    async fn connect_to_endpoint(
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

    async fn connect_to_endpoint(
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
    /// The management server endpoint the client is currently connected to
    #[allow(dead_code)]
    connected_endpoint: Endpoint,
}

impl<C: ServiceClient> Client<C> {
    #[tracing::instrument(skip_all, level = "trace", fields(servers = ?management_servers))]
    pub async fn connect(identifier: String, management_servers: Vec<Endpoint>) -> Result<Self> {
        let (client, connected_endpoint) = Self::connect_with_backoff(&management_servers).await?;
        Ok(Self {
            client,
            identifier: Arc::from(identifier),
            management_servers,
            connected_endpoint,
        })
    }

    async fn connect_with_backoff(management_servers: &[Endpoint]) -> Result<(C, Endpoint)> {
        use crate::config::{
            BACKOFF_INITIAL_DELAY, BACKOFF_MAX_DELAY, BACKOFF_MAX_JITTER, CONNECTION_TIMEOUT,
        };

        let mut backoff = ExponentialBackoff::new(BACKOFF_INITIAL_DELAY);

        let retry_config = RetryFutureConfig::new(u32::MAX).custom_backoff(|attempt, error: &_| {
            tracing::info!(attempt, "Retrying to connect");
            // reset after success
            if attempt <= 1 {
                backoff = ExponentialBackoff::new(BACKOFF_INITIAL_DELAY);
            }

            // max delay + jitter of up to 2 seconds
            let mut delay = backoff.delay(attempt, &error).min(BACKOFF_MAX_DELAY);
            delay += Duration::from_millis(
                rand::thread_rng().gen_range(0..BACKOFF_MAX_JITTER.as_millis() as _),
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
                        tracing::info!("attempting to connect to `{}`", endpoint.uri());
                        let cendpoint = endpoint.clone();
                        let endpoint = endpoint.clone().connect_timeout(CONNECTION_TIMEOUT);

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

                        C::connect_to_endpoint(endpoint)
                            .instrument(tracing::debug_span!(
                                "AggregatedDiscoveryServiceClient::connect_to_endpoint"
                            ))
                            .await
                            .map_err(RpcSessionError::InitialConnect)
                            .map(|client| (client, cendpoint))
                    }
                }
            }
        })
        .with_config(retry_config);

        let client = connect_to_server
            .instrument(tracing::trace_span!("client_connect"))
            .await?;
        tracing::info!("Connected to management server");
        Ok(client)
    }
}

impl MdsClient {
    pub async fn delta_stream<C: crate::config::Configuration>(
        self,
        config: Arc<C>,
        is_healthy: Arc<AtomicBool>,
    ) -> Result<DeltaSubscription, Self> {
        let identifier = String::from(&*self.identifier);

        let (mut ds, mut stream) =
            match DeltaServerStream::connect(self.client.clone(), identifier.clone()).await {
                Ok(ds) => {
                    tracing::debug!("acquired aggregated delta stream");
                    ds
                }
                Err(err) => {
                    tracing::error!(error = ?err, "failed to acquire aggregated delta stream");
                    return Err(self);
                }
            };

        let id = identifier.clone();
        let handle = tokio::task::spawn(
            async move {
                tracing::trace!("starting relay client delta stream task");

                loop {
                    {
                        let control_plane = super::server::ControlPlane::from_arc(
                            config.clone(),
                            IDLE_REQUEST_INTERVAL,
                        );
                        let mut stream = control_plane.delta_aggregated_resources(stream).await?;
                        is_healthy.store(true, Ordering::SeqCst);

                        while let Some(result) = stream.next().await {
                            let response = result?;
                            tracing::debug!("received delta discovery response");
                            ds.send_response(response).await?;
                        }
                    }

                    is_healthy.store(false, Ordering::SeqCst);

                    //tracing::warn!("lost connection to relay server, retrying");
                    let new_client = MdsClient::connect_with_backoff(&self.management_servers)
                        .await
                        .unwrap()
                        .0;
                    (ds, stream) =
                        DeltaServerStream::connect(new_client, identifier.clone()).await?;
                }
            }
            .instrument(tracing::debug_span!("handle_delta_discovery_response", id)),
        );

        Ok(DeltaSubscription { handle })
    }
}

pub(crate) struct DeltaClientStream {
    req_tx: tokio::sync::mpsc::Sender<DeltaDiscoveryRequest>,
}

impl DeltaClientStream {
    #[inline]
    async fn connect(
        mut client: AdsGrpcClient,
        identifier: String,
    ) -> Result<(Self, tonic::Streaming<DeltaDiscoveryResponse>)> {
        let (req_tx, requests_rx) =
            tokio::sync::mpsc::channel(100 /*ResourceType::VARIANTS.len()*/);

        // Since we are doing exploratory requests to see if the remote endpoint supports delta streams, we unfortunately
        // need to actually send something before the full roundtrip occurs. This can be removed once delta discovery
        // is fully rolled out
        req_tx
            .send(DeltaDiscoveryRequest {
                node: Some(Node {
                    id: identifier,
                    user_agent_name: "quilkin".into(),
                    ..Default::default()
                }),
                type_url: "ignore-me".to_owned(),
                ..Default::default()
            })
            .await?;

        let stream = client
            .delta_aggregated_resources(tokio_stream::wrappers::ReceiverStream::new(requests_rx))
            .in_current_span()
            .await?
            .into_inner();

        Ok((Self { req_tx }, stream))
    }

    pub(crate) fn new() -> (Self, tokio::sync::mpsc::Receiver<DeltaDiscoveryRequest>) {
        let (req_tx, requests_rx) = tokio::sync::mpsc::channel(1);
        (Self { req_tx }, requests_rx)
    }

    #[inline]
    pub(crate) async fn refresh(
        &self,
        identifier: &str,
        subs: &[(ResourceType, Vec<String>)],
        local: &crate::config::LocalVersions,
    ) -> Result<()> {
        for (rt, names) in subs {
            let initial_resource_versions = local.get(*rt).clone();
            self.req_tx
                .send(DeltaDiscoveryRequest {
                    node: Some(Node {
                        id: identifier.to_owned(),
                        user_agent_name: "quilkin".into(),
                        ..Node::default()
                    }),
                    type_url: rt.type_url().into(),
                    resource_names_subscribe: names.clone(),
                    initial_resource_versions,
                    // We (currently) never unsubscribe from resources, since we
                    // never actually subscribe to particular ones in the first place
                    resource_names_unsubscribe: Vec::new(),
                    response_nonce: "".into(),
                    error_detail: None,
                })
                .await?;
        }

        Ok(())
    }

    /// Sends an n/ack "response" in response to the remote response
    #[inline]
    pub(crate) async fn send_response(&self, response: DeltaDiscoveryRequest) -> Result<()> {
        self.req_tx.send(response).await?;
        Ok(())
    }
}

pub(crate) struct DeltaServerStream {
    res_tx: tokio::sync::mpsc::Sender<DeltaDiscoveryResponse>,
}

impl DeltaServerStream {
    #[inline]
    async fn connect(
        mut client: MdsGrpcClient,
        identifier: String,
    ) -> Result<(Self, tonic::Streaming<DeltaDiscoveryRequest>)> {
        let (res_tx, responses_rx) = tokio::sync::mpsc::channel(ResourceType::VARIANTS.len());

        res_tx
            .send(DeltaDiscoveryResponse {
                control_plane: Some(crate::core::ControlPlane { identifier }),
                ..Default::default()
            })
            .await?;

        let stream = client
            .delta_aggregated_resources(tokio_stream::wrappers::ReceiverStream::new(responses_rx))
            .in_current_span()
            .await?
            .into_inner();

        Ok((Self { res_tx }, stream))
    }

    #[inline]
    async fn send_response(&self, res: DeltaDiscoveryResponse) -> Result<()> {
        self.res_tx.send(res).await?;
        Ok(())
    }
}

pub struct DeltaSubscription {
    handle: tokio::task::JoinHandle<Result<()>>,
}

impl Drop for DeltaSubscription {
    fn drop(&mut self) {
        tracing::debug!("dropped client delta stream");
        self.handle.abort();
    }
}

impl AdsClient {
    /// Attempts to start a new delta stream to the xDS management server, if the
    /// management server does not support delta xDS we return the client as an error
    pub async fn delta_subscribe<C: crate::config::Configuration>(
        self,
        config: Arc<Config>,
        rt_config: crate::components::proxy::Ready,
        notifier: Option<tokio::sync::mpsc::UnboundedSender<ResourceType>>,
        resources: impl IntoIterator<Item = (ResourceType, Vec<String>)>,
    ) -> Result<DeltaSubscription, Self> {
        let resource_subscriptions: Vec<_> = resources.into_iter().collect();

        let identifier = dbg!(String::from(&*self.identifier));

        let (mut ds, stream) = match DeltaClientStream::connect(
            self.client.clone(),
            identifier.clone(),
        )
        .await
        {
            Ok(ds) => ds,
            Err(err) => {
                tracing::error!(error = ?err, "failed to acquire aggregated delta stream from management server");
                return Err(self);
            }
        };

        // Send requests for our resource subscriptions, in this first request we
        // won't have any resources, but if we reconnect to management servers in
        // the future we'll send the resources we already have locally to hopefully
        // reduce the amount of response data if those resources are already up
        // to date with the current state of the management server
        let local = Arc::new(crate::config::LocalVersions::default());
        if let Err(err) = ds
            .refresh(&identifier, &resource_subscriptions, &local)
            .await
        {
            tracing::error!(error = ?err, "failed to send initial resource requests");
            return Err(self);
        }

        let id = identifier.clone();
        let handle = tokio::task::spawn(
            async move {
                tracing::trace!("starting xDS delta stream task");
                let mut stream = stream;

                loop {
                    tracing::trace!("creating discovery response handler");
                    let mut response_stream = crate::config::handle_delta_discovery_responses(
                        identifier.clone(),
                        stream,
                        config.clone(),
                        local.clone(),
                        None,
                        notifier.clone(),
                    );

                    loop {
                        let next_response =
                            tokio::time::timeout(IDLE_REQUEST_INTERVAL, response_stream.next());

                        match next_response.await {
                            Ok(Some(Ok(response))) => {
                                is_healthy.store(true, Ordering::SeqCst);

                                tracing::trace!("received delta response");
                                ds.send_response(response).await?;
                                continue;
                            }
                            Ok(Some(Err(error))) => {
                                tracing::warn!(%error, "xds stream error");
                                break;
                            }
                            Ok(None) => {
                                tracing::warn!("xDS stream terminated");
                                break;
                            }
                            Err(_) => {
                                tracing::debug!(
                                    "exceeded idle request interval sending new requests"
                                );
                                ds.refresh(&identifier, &resource_subscriptions, &local)
                                    .await?;
                            }
                        }
                    }

                    is_healthy.store(false, Ordering::SeqCst);

                    tracing::info!("Lost connection to xDS, retrying");
                    let (new_client, _) =
                        Self::connect_with_backoff(&self.management_servers).await?;

                    (ds, stream) =
                        DeltaClientStream::connect(new_client, identifier.clone()).await?;
                    ds.refresh(&identifier, &resource_subscriptions, &local)
                        .await?;
                }
            }
            .instrument(tracing::debug_span!("xds_client_stream", id)),
        );

        Ok(DeltaSubscription { handle })
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
    on_new_resource: impl Fn(Resource) -> crate::Result<()> + Send + Sync + 'static,
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
                    (on_new_resource)(resource)
                });

            let error_detail = if let Err(error) = result {
                super::metrics::nacks(&control_plane_identifier, &response.type_url).inc();
                Some(crate::generated::google::rpc::Status {
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
