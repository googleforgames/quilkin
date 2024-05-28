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
use futures::{Stream, TryFutureExt};
use tokio_stream::StreamExt;
use tracing_futures::Instrument;

use crate::{
    discovery::{
        aggregated_discovery_service_server::{
            AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
        },
        DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
    },
    generated::quilkin::relay::v1alpha1::aggregated_control_plane_discovery_service_server::{
        AggregatedControlPlaneDiscoveryService, AggregatedControlPlaneDiscoveryServiceServer,
    },
    metrics,
    net::TcpListener,
    ResourceType,
};

#[derive(Clone)]
pub struct ControlPlane {
    config: Arc<Config>,
    idle_request_interval: Duration,
    tx: tokio::sync::broadcast::Sender<ResourceType>,
    is_relay: bool,
}

impl ControlPlane {
    pub fn from_arc(config: Arc<Config>, idle_request_interval: Duration) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(10);

        Self {
            config,
            idle_request_interval,
            tx,
            is_relay: false,
        }
    }

    fn subscribe_to_config_changes(&self) {
        let id = self.config.id.load().to_string();

        tokio::spawn({
            let this = self.clone();
            async move {
                let mut cluster_watcher = this.config.clusters.watch();
                tracing::debug!("waiting for changes");

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
            .instrument(tracing::debug_span!("control_plane_watch_cluster", id, is_relay = self.is_relay))
        });

        if !self.is_relay {
            self.config.filters.watch({
                let this = self.clone();
                move |_| {
                    this.push_update(ResourceType::Listener);
                }
            });
        }
    }

    pub fn management_server(
        mut self,
        listener: TcpListener,
    ) -> io::Result<impl std::future::Future<Output = crate::Result<()>>> {
        self.is_relay = false;
        self.subscribe_to_config_changes();

        let server = AggregatedDiscoveryServiceServer::new(self)
            .max_encoding_message_size(crate::config::max_grpc_message_size());
        let server = tonic::transport::Server::builder().add_service(server);
        tracing::info!("serving management server on port `{}`", listener.port());
        Ok(server
            .serve_with_incoming(listener.into_stream()?)
            .map_err(From::from))
    }

    pub(crate) fn relay_server(
        mut self,
        listener: TcpListener,
    ) -> io::Result<impl std::future::Future<Output = crate::Result<()>>> {
        self.is_relay = true;
        self.subscribe_to_config_changes();

        let server = AggregatedControlPlaneDiscoveryServiceServer::new(self)
            .max_encoding_message_size(crate::config::max_grpc_message_size());
        let server = tonic::transport::Server::builder().add_service(server);
        tracing::info!("serving relay server on port `{}`", listener.port());
        Ok(server
            .serve_with_incoming(listener.into_stream()?)
            .map_err(From::from))
    }

    #[inline]
    fn push_update(&self, resource_type: ResourceType) {
        tracing::debug!(%resource_type, id=%self.config.id.load(), is_relay = self.is_relay, "pushing update");
        if self.tx.send(resource_type).is_err() {
            tracing::debug!("no client connections currently subscribed");
        }
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
        use crate::{AwaitingAck, ClientVersions};
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
        let mut rx = this.tx.subscribe();

        let id = (*this.config.id.load()).clone();
        tracing::debug!(
            id,
            client = node_id,
            count = this.tx.receiver_count(),
            is_relay = this.is_relay,
            "subscribed to config updates"
        );

        let control_plane_id = crate::net::xds::core::ControlPlane {
            identifier: id.clone(),
        };

        struct ResourceTypeTracker {
            client: ClientVersions,
            subscribed: BTreeSet<String>,
            kind: ResourceType,
            subbed: bool,
        }

        // Keep track of the resource versions that the client has so we can only
        // send the resources that are actually different in each response
        let mut trackers = enum_map::enum_map! {
            ResourceType::Cluster => ResourceTypeTracker {
                client: ClientVersions::new(ResourceType::Cluster),
                subscribed: BTreeSet::new(),
                kind: ResourceType::Cluster,
                subbed: false,
            },
            ResourceType::Listener => {
                ResourceTypeTracker {
                    client: ClientVersions::new(ResourceType::Listener),
                    subscribed: BTreeSet::new(),
                    kind: ResourceType::Listener,
                    subbed: false,
                }
            },
            ResourceType::FilterChain => {
                ResourceTypeTracker {
                    client: ClientVersions::new(ResourceType::FilterChain),
                    subscribed: BTreeSet::new(),
                    kind: ResourceType::FilterChain,
                    subbed: false,
                }
            },
            ResourceType::Datacenter => {
                ResourceTypeTracker {
                    client: ClientVersions::new(ResourceType::Datacenter),
                    subscribed: BTreeSet::new(),
                    kind: ResourceType::Datacenter,
                    subbed: false,
                }
            }
        };

        let client = node_id.clone();
        let responder =
            move |req: Option<DeltaDiscoveryRequest>,
                  tracker: &mut ResourceTypeTracker,
                  pending_acks: &mut cached::TimedSizedCache<uuid::Uuid, AwaitingAck>|
                  -> Result<DeltaDiscoveryResponse, tonic::Status> {
                if let Some(req) = req {
                    metrics::delta_discovery_requests(&client, tracker.kind.type_url()).inc();

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
                } else {
                    tracing::debug!(kind = %tracker.kind, "sending delta update");
                }

                tracker.subbed = true;

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

        let nid = node_id.clone();

        let response = {
            if message.type_url == "ignore-me" {
                tracing::debug!(id, client = nid, "initial delta response");
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
                tracing::debug!(client = %node_id, %resource_type, "initial delta response");
                responder(
                    Some(message),
                    &mut trackers[resource_type],
                    &mut pending_acks,
                )?
            }
        };

        let stream = async_stream::try_stream! {
            yield response;

            loop {
                tokio::select! {
                    // The resource(s) have changed, inform the connected client, but only
                    // send the changed resources that the client doesn't already have
                    res = rx.recv() => {
                        match res {
                            Ok(rt) => {
                                let tracker = &mut trackers[rt];
                                if tracker.subbed {
                                    yield responder(None, tracker, &mut pending_acks)?;
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                for (_, tracker) in &mut trackers {
                                    if tracker.subbed {
                                        yield responder(None, tracker, &mut pending_acks)?;
                                    }
                                }
                            }
                        }
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

                        tracing::trace!(%resource_type, "new delta message");

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

            tracing::info!("terminating stream");
        };

        Ok(Box::pin(stream.instrument(tracing::info_span!(
            "xds_server_stream",
            id,
            client = nid
        ))))
    }
}

#[tonic::async_trait]
impl<C: crate::config::Configuration> AggregatedDiscoveryService for ControlPlane<C> {
    type StreamAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DiscoveryResponse, tonic::Status>> + Send>>;
    type DeltaAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DeltaDiscoveryResponse, tonic::Status>> + Send>>;

    #[tracing::instrument(skip_all)]
    async fn stream_aggregated_resources(
        &self,
        _request: tonic::Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::StreamAggregatedResourcesStream>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "only delta streams are supported",
        ))
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
impl<C: crate::config::Configuration> AggregatedControlPlaneDiscoveryService for ControlPlane<C> {
    type StreamAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DiscoveryRequest, tonic::Status>> + Send>>;
    type DeltaAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DeltaDiscoveryRequest, tonic::Status>> + Send>>;

    #[tracing::instrument(skip_all)]
    async fn stream_aggregated_resources(
        &self,
        _responses: tonic::Request<tonic::Streaming<DiscoveryResponse>>,
    ) -> Result<tonic::Response<Self::StreamAggregatedResourcesStream>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "only delta streams are supported",
        ))
    }

    #[tracing::instrument(skip_all)]
    async fn delta_aggregated_resources(
        &self,
        responses: tonic::Request<tonic::Streaming<DeltaDiscoveryResponse>>,
    ) -> Result<tonic::Response<Self::DeltaAggregatedResourcesStream>, tonic::Status> {
        use crate::ResourceType;

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

                let local = Arc::new(crate::config::LocalVersions::default());

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

                let mut response_stream = crate::config::handle_delta_discovery_responses(
                    identifier.clone(),
                    responses,
                    config.clone(),
                    local.clone(),
                    Some(remote_addr),
                    None,
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
    use crate::{
        core::Node,
            listener::v3::{FilterChain, Listener},
        },
        listener::{FilterChain, Listener},
        ResourceType,
    };

    const TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(10);

    #[tokio::test]
    async fn valid_response() {
        const RESOURCE: ResourceType = ResourceType::Cluster;
        const LISTENER_TYPE: ResourceType = ResourceType::Listener;

        let mut response = DeltaDiscoveryResponse {
            resources: vec![],
            type_url: RESOURCE.type_url().into(),
            ..<_>::default()
        };

        let mut listener_response = DeltaDiscoveryResponse {
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
