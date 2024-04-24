/*
 * Copyright 2022 Google LLC
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

use std::{io, sync::Arc, time::Duration};

use cached::Cached;
use futures::{Stream, TryFutureExt, TryStreamExt};
use tokio_stream::StreamExt;
use tracing_futures::Instrument;

use crate::{
    config::Config,
    net::{
        xds::{
            discovery::{
                aggregated_discovery_service_server::{
                    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
                },
                DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
            },
            metrics,
            relay::aggregated_control_plane_discovery_service_server::{
                AggregatedControlPlaneDiscoveryService,
                AggregatedControlPlaneDiscoveryServiceServer,
            },
            ResourceType,
        },
        TcpListener,
    },
};

#[tracing::instrument(skip_all)]
pub fn spawn(
    listener: TcpListener,
    config: std::sync::Arc<crate::Config>,
    idle_request_interval: Duration,
) -> io::Result<impl std::future::Future<Output = crate::Result<()>>> {
    let server = AggregatedDiscoveryServiceServer::new(ControlPlane::from_arc(
        config,
        idle_request_interval,
    ))
    .max_encoding_message_size(crate::config::max_grpc_message_size());
    let server = tonic::transport::Server::builder().add_service(server);
    tracing::info!("serving management server on port `{}`", listener.port());
    Ok(server
        .serve_with_incoming(listener.into_stream()?)
        .map_err(From::from))
}

pub(crate) fn control_plane_discovery_server(
    listener: TcpListener,
    config: Arc<Config>,
    idle_request_interval: Duration,
) -> io::Result<impl std::future::Future<Output = crate::Result<()>>> {
    let server = AggregatedControlPlaneDiscoveryServiceServer::new(ControlPlane::from_arc(
        config,
        idle_request_interval,
    ))
    .max_encoding_message_size(crate::config::max_grpc_message_size());
    let server = tonic::transport::Server::builder().add_service(server);
    tracing::info!("serving relay server on port `{}`", listener.port());
    Ok(server
        .serve_with_incoming(listener.into_stream()?)
        .map_err(From::from))
}

#[derive(Clone)]
pub struct ControlPlane {
    config: Arc<Config>,
    idle_request_interval: Duration,
    watchers: Arc<crate::net::xds::resource::ResourceMap<Watchers>>,
}

struct Watchers {
    sender: tokio::sync::watch::Sender<()>,
    receiver: tokio::sync::watch::Receiver<()>,
    version: std::sync::atomic::AtomicU64,
}

impl Default for Watchers {
    fn default() -> Self {
        let (sender, receiver) = tokio::sync::watch::channel(());
        Self {
            sender,
            receiver,
            version: <_>::default(),
        }
    }
}

impl ControlPlane {
    pub fn from_arc(config: Arc<Config>, idle_request_interval: Duration) -> Self {
        let this = Self {
            config,
            idle_request_interval,
            watchers: Default::default(),
        };

        tokio::spawn({
            let this = this.clone();
            async move {
                let mut cluster_watcher = this.config.clusters.watch();
                tracing::trace!("waiting for changes");

                match &this.config.datacenter {
                    crate::config::DatacenterConfig::Agent {..} => {
                        loop {
                            match cluster_watcher.changed().await {
                                Ok(()) => this.push_update(ResourceType::Cluster),
                                Err(error) => tracing::error!(%error, "error watching changes"),
                            }
                        }
                    }
                    crate::config::DatacenterConfig::NonAgent { datacenters } => {
                        let mut dc_watcher = datacenters.watch();
                        loop {
                            tokio::select! {
                                result = cluster_watcher.changed() => {
                                    match result {
                                        Ok(()) => this.push_update(ResourceType::Cluster),
                                        Err(error) => tracing::error!(%error, "error watching changes"),
                                    }
                                }
                                result = dc_watcher.changed() => {
                                    match result {
                                        Ok(()) => this.push_update(ResourceType::Datacenter),
                                        Err(error) => tracing::error!(%error, "error watching changes"),
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .instrument(tracing::debug_span!("control_plane_watch_cluster"))
        });

        this.config.filters.watch({
            let this = this.clone();
            move |_| {
                this.push_update(ResourceType::Listener);
            }
        });

        this
    }

    fn push_update(&self, resource_type: ResourceType) {
        let watchers = &self.watchers[resource_type];
        watchers
            .version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::trace!(%resource_type, watchers=watchers.sender.receiver_count(), "pushing update");
        if let Err(error) = watchers.sender.send(()) {
            tracing::warn!(%error, "pushing update failed");
        }
    }

    pub(crate) fn discovery_response(
        &self,
        id: &str,
        resource_type: ResourceType,
        names: &[String],
    ) -> Result<DiscoveryResponse, tonic::Status> {
        let resources = self
            .config
            .discovery_request(id, resource_type, names)
            .map_err(|error| tonic::Status::internal(error.to_string()))?;
        let watchers = &self.watchers[resource_type];

        let response = DiscoveryResponse {
            resources,
            nonce: uuid::Uuid::new_v4().to_string(),
            version_info: watchers
                .version
                .load(std::sync::atomic::Ordering::Relaxed)
                .to_string(),
            control_plane: Some(crate::net::xds::core::ControlPlane {
                identifier: (*self.config.id.load()).clone(),
            }),
            type_url: resource_type.type_url().to_owned(),
            canary: false,
        };

        tracing::trace!(
            id = &*response.version_info,
            r#type = &*response.type_url,
            nonce = &*response.nonce,
            "discovery response"
        );

        Ok(response)
    }

    pub async fn stream_resources<S>(
        &self,
        mut streaming: S,
    ) -> Result<impl Stream<Item = Result<DiscoveryResponse, tonic::Status>> + Send, tonic::Status>
    where
        S: Stream<Item = Result<DiscoveryRequest, tonic::Status>>
            + Send
            + std::marker::Unpin
            + 'static,
    {
        tracing::trace!("starting stream");
        let message = streaming.next().await.ok_or_else(|| {
            tracing::error!("No message found");
            tonic::Status::invalid_argument("No message found")
        })??;

        if message.node.is_none() {
            tracing::error!("Node identifier was not found");
            return Err(tonic::Status::invalid_argument("Node identifier required"));
        }

        let node = message.node.clone().unwrap();
        let resource_type: ResourceType = message.type_url.parse()?;
        let mut rx = self.watchers[resource_type].receiver.clone();
        let mut pending_acks = cached::TimedSizedCache::with_size_and_lifespan(50, 1);
        let this = Self::clone(self);
        let id = node.id.clone();

        tracing::debug!(id = %node.id, %resource_type, "initial request");
        metrics::discovery_requests(&id, resource_type.type_url()).inc();
        let response = this.discovery_response(&id, resource_type, &message.resource_names)?;
        pending_acks.cache_set(response.nonce.clone(), ());

        Ok(Box::pin(async_stream::try_stream! {
            yield response;

            loop {
                tokio::select! {
                    _ = rx.changed() => {
                        tracing::trace!("sending new discovery response");
                        yield this.discovery_response(&id, resource_type, &message.resource_names).map(|response| {
                            pending_acks.cache_set(response.nonce.clone(), ());
                            response
                        })?;
                    }
                    new_message = streaming.next() => {
                        let new_message = match new_message.transpose() {
                            Ok(Some(value)) => value,
                            Ok(None) => break,
                            Err(error) => {
                                tracing::error!(%error, "error receiving message");
                                continue;
                            }
                        };

                        tracing::trace!("new message");
                        let id = new_message.node.as_ref().map(|node| &*node.id).unwrap_or(&*id);
                        let resource_type = match new_message.type_url.parse::<ResourceType>() {
                            Ok(value) => value,
                            Err(error) => {
                                tracing::error!(%error, url = %new_message.type_url, "unknown resource type");
                                continue;
                            }
                        };

                        metrics::discovery_requests(id, resource_type.type_url()).inc();

                        if let Some(error) = &new_message.error_detail {
                            metrics::nacks(id, resource_type.type_url()).inc();
                            tracing::error!(nonce = %new_message.response_nonce, ?error, "NACK");
                            // Currently just resend previous discovery response.
                        } else if uuid::Uuid::parse_str(&new_message.response_nonce).is_ok() {
                            if pending_acks.cache_get(&new_message.response_nonce).is_some() {
                                tracing::debug!(nonce = %new_message.response_nonce, "ACK");
                                continue
                            } else {
                                tracing::trace!(nonce = %new_message.response_nonce, "Unknown nonce: could not be found in cache");
                                continue
                            }
                        }

                        yield this.discovery_response(id, resource_type, &message.resource_names).map(|response| {
                            pending_acks.cache_set(response.nonce.clone(), ());
                            response
                        }).unwrap();
                    }
                }
            }

            tracing::info!("terminating stream");
        }.instrument(tracing::info_span!("xds_stream", %node.id, %resource_type))))
    }

    pub async fn delta_aggregated_resources<S>(
        &self,
        mut streaming: S,
    ) -> Result<
        impl Stream<Item = Result<DeltaDiscoveryResponse, tonic::Status>> + Send,
        tonic::Status,
    >
    where
        S: Stream<Item = Result<DeltaDiscoveryRequest, tonic::Status>>
            + Send
            + std::marker::Unpin
            + 'static,
    {
        use crate::net::xds::{AwaitingAck, ClientVersions};
        use std::collections::BTreeSet;

        tracing::debug!("starting delta stream");
        let message = streaming.next().await.ok_or_else(|| {
            tracing::error!("No message found");
            tonic::Status::invalid_argument("No message found")
        })??;

        let node_id = if let Some(node) = &message.node {
            node.id.clone()
        } else {
            tracing::error!("Node identifier was not found");
            return Err(tonic::Status::invalid_argument("Node identifier required"));
        };

        let mut pending_acks = cached::TimedSizedCache::with_size_and_lifespan(50, 1);
        let this = Self::clone(self);

        let control_plane_id = crate::net::xds::core::ControlPlane {
            identifier: (*this.config.id.load()).clone(),
        };

        struct ResourceTypeTracker {
            client: ClientVersions,
            subscribed: BTreeSet<String>,
            kind: ResourceType,
        }

        // Keep track of the resource versions that the client has so we can only
        // send the resources that are actually different in each response
        let mut trackers = enum_map::enum_map! {
            ResourceType::Cluster => ResourceTypeTracker {
                client: ClientVersions::new(ResourceType::Cluster),
                subscribed: BTreeSet::new(),
                kind: ResourceType::Cluster,
            },
            ResourceType::Listener => {
                ResourceTypeTracker {
                    client: ClientVersions::new(ResourceType::Listener),
                    subscribed: BTreeSet::new(),
                    kind: ResourceType::Listener,
                }
            }
            ResourceType::Datacenter => {
                ResourceTypeTracker {
                    client: ClientVersions::new(ResourceType::Datacenter),
                    subscribed: BTreeSet::new(),
                    kind: ResourceType::Datacenter,
                }
            }
        };

        let mut cluster_rx = self.watchers[ResourceType::Cluster].receiver.clone();
        let mut listener_rx = self.watchers[ResourceType::Listener].receiver.clone();
        let mut dc_rx = self.watchers[ResourceType::Datacenter].receiver.clone();

        let id = node_id.clone();
        let responder =
            move |req: Option<DeltaDiscoveryRequest>,
                  tracker: &mut ResourceTypeTracker,
                  pending_acks: &mut cached::TimedSizedCache<uuid::Uuid, AwaitingAck>|
                  -> Result<DeltaDiscoveryResponse, tonic::Status> {
                if let Some(req) = req {
                    metrics::delta_discovery_requests(&id, tracker.kind.type_url()).inc();

                    // If the request has filled out the initial_versions field, it means the connected management servers has
                    // already had a connection with a control plane, so hard reset our state to what it says it has
                    if !req.initial_resource_versions.is_empty() {
                        tracker
                            .client
                            .reset(req.initial_resource_versions)
                            .map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
                    }

                    // From the spec:
                    // A resource_names_subscribe field may contain resource names that
                    // the server believes the client is already subscribed to, and
                    // furthermore has the most recent versions of. However, the server
                    // must still provide those resources in the response; due to
                    // implementation details hidden from the server, the client may
                    // have “forgotten” those resources despite apparently remaining subscribed.
                    if !req.resource_names_subscribe.is_empty() {
                        for sub in req.resource_names_subscribe {
                            tracker.subscribed.insert(sub.clone());
                            tracker.client.remove(sub);
                        }
                    }

                    if !req.resource_names_unsubscribe.is_empty() {
                        for sub in req.resource_names_unsubscribe {
                            tracker.subscribed.remove(&sub);
                            tracker.client.remove(sub);
                        }
                    }
                }

                let req = this
                    .config
                    .delta_discovery_request(&tracker.subscribed, &tracker.client)
                    .map_err(|error| tonic::Status::internal(error.to_string()))?;

                let nonce = uuid::Uuid::new_v4();
                pending_acks.cache_set(nonce, req.awaiting_ack);

                let response = DeltaDiscoveryResponse {
                    resources: req.resources,
                    nonce: nonce.to_string(),
                    control_plane: Some(control_plane_id.clone()),
                    type_url: tracker.kind.type_url().to_owned(),
                    removed_resources: req.removed,
                    // Only used for debugging, not really useful
                    system_version_info: String::new(),
                };

                tracing::trace!(
                    r#type = &*response.type_url,
                    nonce = &*response.nonce,
                    "delta discovery response"
                );

                Ok(response)
            };

        let response = {
            if message.type_url == "ignore-me" {
                tracing::debug!(id = %node_id, "initial delta response");
                DeltaDiscoveryResponse {
                    resources: Vec::new(),
                    nonce: String::new(),
                    control_plane: None,
                    type_url: message.type_url,
                    removed_resources: Vec::new(),
                    // Only used for debugging, not really useful
                    system_version_info: String::new(),
                }
            } else {
                let resource_type: ResourceType = message.type_url.parse()?;
                tracing::debug!(id = %node_id, %resource_type, "initial delta response");
                responder(
                    Some(message),
                    &mut trackers[resource_type],
                    &mut pending_acks,
                )?
            }
        };

        let nid = node_id.clone();
        let stream = async_stream::try_stream! {
            yield response;

            loop {
                tokio::select! {
                    // The resource(s) have changed, inform the connected client, but only
                    // send the changed resources that the client doesn't already have
                    _ = cluster_rx.changed() => {
                        tracing::trace!("sending new cluster delta discovery response");

                        yield responder(None, &mut trackers[ResourceType::Cluster], &mut pending_acks)?;
                    }
                    _ = listener_rx.changed() => {
                        tracing::trace!("sending new listener delta discovery response");

                        yield responder(None, &mut trackers[ResourceType::Listener], &mut pending_acks)?;
                    }
                    _ = dc_rx.changed() => {
                        tracing::trace!("sending new datacenter delta discovery response");

                        yield responder(None, &mut trackers[ResourceType::Datacenter], &mut pending_acks)?;
                    }
                    client_request = streaming.next() => {
                        let client_request = match client_request.transpose() {
                            Ok(Some(value)) => value,
                            Ok(None) => break,
                            Err(error) => {
                                tracing::error!(%error, "error receiving delta response");
                                continue;
                            }
                        };

                        if client_request.type_url == "ignore-me" {
                            continue;
                        }

                        let id = client_request.node.as_ref().map(|node| node.id.as_str()).unwrap_or(node_id.as_str());
                        let resource_type: ResourceType = match client_request.type_url.parse() {
                            Ok(value) => value,
                            Err(error) => {
                                tracing::error!(%error, url=%client_request.type_url, "unknown resource type");
                                continue;
                            }
                        };

                        tracing::trace!(id, %resource_type, "new delta message");

                        let tracker = &mut trackers[resource_type];

                        if let Some(error) = &client_request.error_detail {
                            metrics::nacks(id, resource_type.type_url()).inc();
                            tracing::error!(nonce = %client_request.response_nonce, ?error, "NACK");
                        } else if let Ok(nonce) = uuid::Uuid::parse_str(&client_request.response_nonce) {
                            if let Some(to_ack) = pending_acks.cache_remove(&nonce) {
                                tracing::trace!(%nonce, "ACK");
                                tracker.client.ack(to_ack);
                            } else {
                                tracing::trace!(%nonce, "Unknown nonce: could not be found in cache");
                            }

                            metrics::delta_discovery_requests(id, resource_type.type_url()).inc();
                            continue;
                        }

                        yield responder(Some(client_request), tracker, &mut pending_acks).unwrap();
                    }
                }
            }

            tracing::info!("terminating delta stream");
        };

        Ok(Box::pin(stream.instrument(
            tracing::info_span!("xds_delta_stream", id = %nid),
        )))
    }
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for ControlPlane {
    type StreamAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DiscoveryResponse, tonic::Status>> + Send>>;
    type DeltaAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DeltaDiscoveryResponse, tonic::Status>> + Send>>;

    #[tracing::instrument(skip_all)]
    async fn stream_aggregated_resources(
        &self,
        request: tonic::Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::StreamAggregatedResourcesStream>, tonic::Status> {
        Ok(tonic::Response::new(Box::pin(
            self.stream_resources(request.into_inner())
                .in_current_span()
                .await?,
        )))
    }

    #[tracing::instrument(skip_all)]
    async fn delta_aggregated_resources(
        &self,
        request: tonic::Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::DeltaAggregatedResourcesStream>, tonic::Status> {
        Ok(tonic::Response::new(Box::pin(
            self.delta_aggregated_resources(request.into_inner())
                .in_current_span()
                .await?,
        )))
    }
}

#[tonic::async_trait]
impl AggregatedControlPlaneDiscoveryService for ControlPlane {
    type StreamAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DiscoveryRequest, tonic::Status>> + Send>>;
    type DeltaAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DeltaDiscoveryRequest, tonic::Status>> + Send>>;

    #[tracing::instrument(skip_all)]
    async fn stream_aggregated_resources(
        &self,
        responses: tonic::Request<tonic::Streaming<DiscoveryResponse>>,
    ) -> Result<tonic::Response<Self::StreamAggregatedResourcesStream>, tonic::Status> {
        let mut remote_addr = responses
            .remote_addr()
            .ok_or_else(|| tonic::Status::invalid_argument("no remote address available"))?;
        remote_addr.set_ip(remote_addr.ip().to_canonical());
        let mut responses = responses.into_inner();
        let Some(identifier) = responses
            .next()
            .await
            .ok_or_else(|| tonic::Status::cancelled("received empty first response"))??
            .control_plane
            .map(|cp| cp.identifier)
        else {
            return Err(tonic::Status::invalid_argument(
                "DiscoveryResponse.control_plane.identifier is required in the first message",
            ));
        };

        tracing::info!(%identifier, "new control plane discovery stream");
        let config = self.config.clone();
        let idle_request_interval = self.idle_request_interval;
        let stream = super::client::AdsStream::connect(
            Arc::from(&*identifier),
            move |(mut requests, _rx), _subscribed_resources| async move {
                tracing::info!(%identifier, "sending initial discovery request");
                crate::net::xds::client::MdsStream::discovery_request_without_cache(
                    &identifier,
                    &mut requests,
                    crate::net::xds::ResourceType::Cluster,
                    &[],
                )
                .map_err(|error| tonic::Status::internal(error.to_string()))?;

                crate::net::xds::client::MdsStream::discovery_request_without_cache(
                    &identifier,
                    &mut requests,
                    crate::net::xds::ResourceType::Datacenter,
                    &[],
                )
                .map_err(|error| tonic::Status::internal(error.to_string()))?;

                let mut response_handler = super::client::handle_discovery_responses(
                    identifier.clone(),
                    responses,
                    move |mut resource| {
                        resource.add_host_to_datacenter(remote_addr);
                        config.apply(resource)
                    },
                );

                loop {
                    let next_response =
                        tokio::time::timeout(idle_request_interval, response_handler.next());

                    if let Ok(Some(ack)) = next_response.await {
                        tracing::trace!("sending ack request");
                        requests.send(ack?)?;
                    } else {
                        tracing::trace!("exceeded idle interval, sending request");
                        crate::net::xds::client::MdsStream::discovery_request_without_cache(
                            &identifier,
                            &mut requests,
                            crate::net::xds::ResourceType::Cluster,
                            &[],
                        )
                        .map_err(|error| tonic::Status::internal(error.to_string()))?;
                    }
                }
            },
        );

        Ok(tonic::Response::new(Box::pin(async_stream::stream! {
            for await request in tokio_stream::wrappers::BroadcastStream::new(stream.requests().subscribe())
                .map_err(|error| tonic::Status::internal(error.to_string()))
            {
                yield request;
            }
        })))
    }

    #[tracing::instrument(skip_all)]
    async fn delta_aggregated_resources(
        &self,
        responses: tonic::Request<tonic::Streaming<DeltaDiscoveryResponse>>,
    ) -> Result<tonic::Response<Self::DeltaAggregatedResourcesStream>, tonic::Status> {
        use crate::net::xds::ResourceType;

        let remote_addr = responses
            .remote_addr()
            .ok_or_else(|| tonic::Status::invalid_argument("no remote address available"))?;

        tracing::info!("control plane discovery delta stream attempt");
        let mut responses = responses.into_inner();
        let Some(identifier) = responses
            .next()
            .await
            .ok_or_else(|| tonic::Status::cancelled("received empty first response"))??
            .control_plane
            .map(|cp| cp.identifier)
        else {
            return Err(tonic::Status::invalid_argument(
                "DeltaDiscoveryResponse.control_plane.identifier is required in the first message",
            ));
        };

        tracing::info!(identifier, "new control plane delta discovery stream");
        let config = self.config.clone();
        let idle_request_interval = self.idle_request_interval;

        let (ds, mut request_stream) = super::client::DeltaClientStream::new();

        let _handle: tokio::task::JoinHandle<crate::Result<()>> = tokio::task::spawn(
            async move {
                tracing::info!(identifier, "sending initial delta discovery request");

                let local = Arc::new(crate::config::xds::LocalVersions::default());

                ds.refresh(
                    &identifier,
                    &[
                        (ResourceType::Cluster, Vec::new()),
                        (ResourceType::Datacenter, Vec::new()),
                    ],
                    &local,
                )
                .await
                .map_err(|error| tonic::Status::internal(error.to_string()))?;

                let mut response_stream = crate::config::xds::handle_delta_discovery_responses(
                    identifier.clone(),
                    responses,
                    config.clone(),
                    local.clone(),
                    Some(remote_addr),
                );

                loop {
                    let next_response =
                        tokio::time::timeout(idle_request_interval, response_stream.next());

                    if let Ok(Some(ack)) = next_response.await {
                        tracing::trace!("sending ack request");
                        ds.send_response(ack?)
                            .await
                            .map_err(|_| tonic::Status::internal("this should not be reachable"))?;
                    } else {
                        tracing::trace!("exceeded idle interval, sending request");
                        ds.refresh(
                            &identifier,
                            &[
                                (ResourceType::Cluster, Vec::new()),
                                (ResourceType::Datacenter, Vec::new()),
                            ],
                            &local,
                        )
                        .await
                        .map_err(|error| tonic::Status::internal(error.to_string()))?;
                    }
                }
            }
            .instrument(tracing::trace_span!("handle_delta_discovery_response")),
        );

        Ok(tonic::Response::new(Box::pin(async_stream::stream! {
            loop {
                let Some(req) = request_stream.recv().await else { break; };
                yield Ok(req);
            }
        })))
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use tokio::time::timeout;

    use super::*;
    use crate::net::xds::{
        core::Node,
        //     listener::v3::{FilterChain, Listener},
        // },
        discovery::DiscoveryResponse,
        listener::{FilterChain, Listener},
        ResourceType,
    };

    const TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(10);

    #[tokio::test]
    async fn valid_response() {
        const RESOURCE: ResourceType = ResourceType::Cluster;
        const LISTENER_TYPE: ResourceType = ResourceType::Listener;

        let mut response = DiscoveryResponse {
            version_info: String::new(),
            resources: vec![],
            type_url: RESOURCE.type_url().into(),
            ..<_>::default()
        };

        let mut listener_response = DiscoveryResponse {
            version_info: String::new(),
            resources: vec![prost_types::Any {
                type_url: LISTENER_TYPE.type_url().into(),
                value: crate::codec::prost::encode(&Listener {
                    filter_chains: vec![FilterChain {
                        filters: vec![],
                        ..<_>::default()
                    }],
                    ..<_>::default()
                })
                .unwrap(),
            }],
            type_url: LISTENER_TYPE.type_url().into(),
            ..<_>::default()
        };

        let config = Arc::new(Config::default_non_agent());
        let client = ControlPlane::from_arc(config.clone(), TIMEOUT_DURATION);
        let (tx, rx) = tokio::sync::mpsc::channel(256);

        let mut request = DiscoveryRequest {
            node: Some(Node {
                id: "quilkin".into(),
                user_agent_name: "quilkin".into(),
                ..Node::default()
            }),
            resource_names: vec![],
            type_url: RESOURCE.type_url().into(),
            ..DiscoveryRequest::default()
        };

        let mut listener_request = DiscoveryRequest {
            node: Some(Node {
                id: "quilkin".into(),
                user_agent_name: "quilkin".into(),
                ..Node::default()
            }),
            resource_names: vec![],
            type_url: LISTENER_TYPE.type_url().into(),
            ..DiscoveryRequest::default()
        };

        timeout(TIMEOUT_DURATION, tx.send(Ok(request.clone())))
            .await
            .unwrap()
            .unwrap();

        let mut stream = timeout(
            TIMEOUT_DURATION,
            client.stream_resources(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx))),
        )
        .await
        .unwrap()
        .unwrap();

        let message = timeout(TIMEOUT_DURATION, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        response.version_info = message.version_info.clone();
        response.nonce = message.nonce.clone();
        response.control_plane = message.control_plane.clone();
        request.response_nonce = message.nonce.clone();

        assert_eq!(response, message);

        timeout(TIMEOUT_DURATION, tx.send(Ok(request.clone())))
            .await
            .unwrap()
            .unwrap();

        timeout(TIMEOUT_DURATION, tx.send(Ok(listener_request.clone())))
            .await
            .unwrap()
            .unwrap();

        let message = timeout(TIMEOUT_DURATION, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        listener_response.control_plane = message.control_plane.clone();
        listener_response.version_info = message.version_info.clone();
        listener_response.nonce = message.nonce.clone();
        listener_request.response_nonce = message.nonce.clone();

        assert_eq!(listener_response, message);

        timeout(TIMEOUT_DURATION, tx.send(Ok(listener_request.clone())))
            .await
            .unwrap()
            .unwrap();
    }
}
