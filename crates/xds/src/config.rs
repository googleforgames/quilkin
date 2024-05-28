use crate::{
    discovery::{DeltaDiscoveryRequest, DeltaDiscoveryResponse},
    ResourceType,
};
use enum_map::Enum as _;
use std::{collections::HashMap, sync::Arc, time::Duration};

pub(crate) const BACKOFF_INITIAL_DELAY: Duration = Duration::from_millis(500);
pub(crate) const BACKOFF_MAX_DELAY: Duration = Duration::from_secs(30);
pub(crate) const BACKOFF_MAX_JITTER: Duration = Duration::from_millis(2000);
pub(crate) const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Returns the configured maximum allowed message size for gRPC messages.
/// When using State Of The World xDS, the message size can get large enough
/// that it can exceed the default limits.
pub fn max_grpc_message_size() -> usize {
    std::env::var("QUILKIN_MAX_GRPC_MESSAGE_SIZE")
        .as_deref()
        .ok()
        .and_then(|var| var.parse().ok())
        .unwrap_or(256 * 1024 * 1024)
}

/// Keeps tracking of the local versions of each resource sent from the management
/// server, allowing reconnections to the same/new management servers to send initial
/// versions to reduce the initial response size
#[derive(Default)]
pub struct LocalVersions {
    versions: [parking_lot::Mutex<HashMap<String, String>>; ResourceType::VARIANTS.len()],
}

impl LocalVersions {
    #[inline]
    pub fn get(&self, ty: ResourceType) -> parking_lot::MutexGuard<'_, HashMap<String, String>> {
        self.versions[ty.into_usize()].lock()
    }
}

pub trait Configuration: Send + Sync + Sized + 'static {
    fn identifier(&self) -> String;
    fn apply(&self, response: crate::Resource) -> crate::Result<()>;

    fn apply_delta(
        &self,
        resource_type: ResourceType,
        resources: impl Iterator<Item = crate::Result<(crate::Resource, String)>>,
        removed_resources: Vec<String>,
        local_versions: &mut HashMap<String, String>,
    ) -> crate::Result<()>;

    fn discovery_request(
        &self,
        _node_id: &str,
        resource_type: ResourceType,
        names: &[String],
    ) -> Result<Vec<prost_types::Any>, eyre::Error>;

    fn delta_discovery_request(
        &self,
        subscribed: &std::collections::BTreeSet<String>,
        client_versions: &crate::ClientVersions,
    ) -> crate::Result<DeltaDiscoveryRes>;

    fn on_changed(
        &self,
        subscribed: crate::server::ControlPlane<Self>,
    ) -> impl std::future::Future<Output = ()> + Send + 'static;
}

pub struct DeltaDiscoveryRes {
    pub resources: Vec<crate::generated::envoy::service::discovery::v3::Resource>,
    pub awaiting_ack: crate::AwaitingAck,
    pub removed: Vec<String>,
}

/// Processes responses from management servers, applying resources to the proxy
#[tracing::instrument(skip_all, fields(identifier))]
pub fn handle_delta_discovery_responses<C: Configuration>(
    identifier: String,
    stream: impl futures::Stream<Item = tonic::Result<DeltaDiscoveryResponse>> + 'static + Send,
    config: Arc<C>,
    local: Arc<LocalVersions>,
    remote_addr: Option<std::net::SocketAddr>,
    mut notifier: Option<tokio::sync::mpsc::UnboundedSender<ResourceType>>,
) -> std::pin::Pin<Box<dyn futures::Stream<Item = crate::Result<DeltaDiscoveryRequest>> + Send>> {
    Box::pin(async_stream::try_stream! {
        let _stream_metrics = crate::metrics::StreamConnectionMetrics::new(identifier.clone());
        tracing::trace!("awaiting delta response");
        for await response in stream
        {
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(%error, "Error from xDS server");
                    break;
                }
            };

            if response.type_url == "ignore-me" {
                continue;
            }

            let control_plane_identifier = response.control_plane.as_ref().map(|cp| cp.identifier.as_str()).unwrap_or_default();

            crate::metrics::delta_discovery_responses(control_plane_identifier, &response.type_url).inc();
            tracing::trace!(
                version = &*response.system_version_info,
                r#type = &*response.type_url,
                nonce = &*response.nonce,
                "received delta response"
            );

            let resource_type = ResourceType::try_from(&response.type_url)?;
            let map = &local.versions[resource_type.into_usize()];

            let result = {
                tracing::trace!(num_resources = response.resources.len(), kind = %resource_type, "applying delta resources");
                let mut lock = map.lock();

                config.apply_delta(
                    resource_type,
                    response
                    .resources
                    .into_iter()
                    .map(|res| {
                        crate::Resource::try_from(res.resource.ok_or_else(|| eyre::format_err!("resource field not set"))?).map(|mut rsrc| {
                            if let Some(ra) = remote_addr {
                                rsrc.add_host_to_datacenter(ra);
                            }
                            (rsrc, res.version)
                        })
                    }), response.removed_resources, &mut lock)
            };

            if let Some(note) = &notifier {
                if note.send(resource_type).is_err() {
                    notifier = None;
                }
            }

            let error_detail = if let Err(error) = result {
                crate::metrics::nacks(control_plane_identifier, &response.type_url).inc();
                Some(crate::generated::google::rpc::Status {
                    code: 3,
                    message: error.to_string(),
                    ..Default::default()
                })
            } else {
                crate::metrics::acks(control_plane_identifier, &response.type_url).inc();
                None
            };

            yield DeltaDiscoveryRequest {
                type_url: response.type_url,
                response_nonce: response.nonce,
                error_detail,
                ..Default::default()
            }
        }
    })
}
