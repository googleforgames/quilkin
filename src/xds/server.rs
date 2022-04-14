use std::{pin::Pin, sync::Arc};

use cached::{Cached, CachedAsync};
use futures::Stream;
use tokio_stream::StreamExt;

use crate::xds::{
    service::discovery::v3::{
        aggregated_discovery_service_server::AggregatedDiscoveryService, DeltaDiscoveryRequest,
        DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
    },
    Cache, DiscoveryServiceProvider, ResourceType,
};

pub struct ControlPlane {
    provider: Arc<dyn DiscoveryServiceProvider>,
}

impl ControlPlane {
    /// Creates a new server for a [DiscoveryServiceProvider].
    pub fn new<P: DiscoveryServiceProvider + 'static>(provider: P) -> Self {
        Self {
            provider: Arc::from(provider),
        }
    }

    /// Creates a new server from a dynamic reference
    /// counted [DiscoveryServiceProvider].
    pub fn from_arc(provider: Arc<dyn DiscoveryServiceProvider>) -> Self {
        Self { provider }
    }

    /// Creates a new server for a [DiscoveryServiceProvider] with a cache.
    pub fn with_cache<P: DiscoveryServiceProvider + 'static>(provider: P) -> Self {
        Self::new(Cache::new(provider))
    }

    pub async fn stream_aggregated_resources(
        &self,
        mut streaming: Pin<Box<dyn Stream<Item = Result<DiscoveryRequest, tonic::Status>> + Send>>,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<DiscoveryResponse, tonic::Status>> + Send>>,
        tonic::Status,
    > {
        let message = streaming
            .next()
            .await
            .ok_or_else(|| tonic::Status::invalid_argument("No message found"))??;

        if message.node.is_none() {
            return Err(tonic::Status::invalid_argument("Node identifier required"));
        }

        let node = message.node.clone().unwrap();
        let resource_type = ResourceType::try_from(&message.type_url)?;
        let provider = self.provider.clone();

        Ok(Box::pin(async_stream::try_stream! {
            // Short cache for inflight requests that have yet to be ACKed.
            let mut inflight_cache = cached::TimedCache::with_lifespan(5);
            let mut resource_versions = std::collections::HashMap::<ResourceType, u64>::new();
            let version = resource_versions.get(&resource_type).copied().unwrap_or_default();
            let mut response = provider.discovery_request(&node.id, version, resource_type, &message.resource_names).await?;
            let nonce = uuid::Uuid::new_v4();
            response.nonce = nonce.to_string();

            inflight_cache.cache_set(nonce, response.clone());

            yield response;

            while let Some(new_message) = streaming.next().await.transpose()? {
                let resource_type = ResourceType::try_from(&new_message.type_url)?;
                let mut version: u64 = resource_versions.get(&resource_type).copied().unwrap_or_default();
                let mut response = if let Some(error) = &new_message.error_detail {
                    tracing::error!(error=&*error.message, "NACK");
                    // Currently just resend previous discovery response.
                    let nonce = uuid::Uuid::parse_str(&new_message.response_nonce).map_err(|err| tonic::Status::invalid_argument(err.to_string()))?;
                    inflight_cache.try_get_or_set_with(nonce.clone(), ||{
                        provider.discovery_request(&node.id, version, resource_type, &message.resource_names)
                    }).await?.clone()
                } else {
                    if let Ok(uuid) = uuid::Uuid::parse_str(&new_message.response_nonce) {
                        if inflight_cache.cache_get(&uuid).is_some() {
                            tracing::info!(version=&*new_message.version_info, "ACK");
                            inflight_cache.cache_remove(&uuid);
                            continue;
                        } else {
                            Err(tonic::Status::invalid_argument("Unknown nonce"))?;
                            continue;
                        }
                    } else {
                        version += 1;
                        provider.discovery_request(&node.id, version, resource_type, &new_message.resource_names).await?
                    }
                };

                resource_versions.insert(resource_type, version);
                response.nonce = uuid::Uuid::new_v4().to_string();
                inflight_cache.cache_set(nonce, response.clone());
                yield response;
            }
        }))
    }
}

#[tonic::async_trait]
impl AggregatedDiscoveryService for ControlPlane {
    type StreamAggregatedResourcesStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<DiscoveryResponse, tonic::Status>> + Send>>;
    type DeltaAggregatedResourcesStream =
        tokio_stream::wrappers::ReceiverStream<Result<DeltaDiscoveryResponse, tonic::Status>>;

    #[tracing::instrument(skip(self))]
    async fn stream_aggregated_resources(
        &self,
        request: tonic::Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::StreamAggregatedResourcesStream>, tonic::Status> {
        let streaming = request.into_inner();

        Ok(tonic::Response::new(
            self.stream_aggregated_resources(Box::pin(streaming))
                .await?,
        ))
    }

    async fn delta_aggregated_resources(
        &self,
        _request: tonic::Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::DeltaAggregatedResourcesStream>, tonic::Status> {
        Err(tonic::Status::unimplemented(
            "Quilkin doesn't currently support Delta xDS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::timeout;

    use super::*;
    use crate::{
        test_utils::TestProvider,
        xds::{
            config::{
                cluster::v3::{
                    cluster::{ClusterDiscoveryType, DiscoveryType},
                    Cluster,
                },
                core::v3::Node,
                endpoint::v3::{ClusterLoadAssignment, LocalityLbEndpoints},
                listener::v3::{FilterChain, Listener},
            },
            service::discovery::v3::DiscoveryResponse,
            ResourceType,
        },
    };

    const TIMEOUT_DURATION: std::time::Duration = std::time::Duration::from_secs(10);

    #[tokio::test]
    async fn valid_response() {
        const RESOURCE: ResourceType = ResourceType::Endpoint;
        const LISTENER_TYPE: ResourceType = ResourceType::Listener;

        let mut response = DiscoveryResponse {
            version_info: 0u8.to_string(),
            resources: vec![prost_types::Any {
                type_url: RESOURCE.type_url().into(),
                value: crate::prost::encode(&Cluster {
                    name: "quilkin".into(),
                    load_assignment: Some(ClusterLoadAssignment {
                        cluster_name: "quilkin".into(),
                        endpoints: vec![LocalityLbEndpoints { ..<_>::default() }],
                        ..<_>::default()
                    }),
                    cluster_discovery_type: Some(ClusterDiscoveryType::Type(
                        DiscoveryType::Static as i32,
                    )),
                    ..<_>::default()
                })
                .unwrap(),
            }],
            type_url: RESOURCE.type_url().into(),
            ..<_>::default()
        };

        let mut listener_response = DiscoveryResponse {
            version_info: 0u8.to_string(),
            resources: vec![prost_types::Any {
                type_url: LISTENER_TYPE.type_url().into(),
                value: crate::prost::encode(&Listener {
                    filter_chains: vec![FilterChain {
                        filters: vec![],
                        ..<_>::default()
                    }],
                    ..<_>::default()
                })
                .unwrap(),
            }],
            type_url: RESOURCE.type_url().into(),
            ..<_>::default()
        };

        let provider = TestProvider::new(<_>::from([
            (RESOURCE, response.clone()),
            (LISTENER_TYPE, listener_response.clone()),
        ]));
        let client = ControlPlane::new(provider);
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
            client.stream_aggregated_resources(Box::pin(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            )),
        )
        .await
        .unwrap()
        .unwrap();

        let message = timeout(TIMEOUT_DURATION, stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        response.nonce = message.nonce.clone();
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
        listener_response.nonce = message.nonce.clone();
        listener_request.response_nonce = message.nonce.clone();

        assert_eq!(listener_response, message);

        timeout(TIMEOUT_DURATION, tx.send(Ok(listener_request.clone())))
            .await
            .unwrap()
            .unwrap();
    }
}
