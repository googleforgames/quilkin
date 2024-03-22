use super::Config;
use crate::net::xds::{
    discovery::{DeltaDiscoveryRequest, DeltaDiscoveryResponse},
    metrics, Resource, ResourceType,
};
use enum_map::Enum as _;
use std::{collections::HashMap, sync::Arc};

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

/// Processes responses from management servers, applying resources to the proxy
#[tracing::instrument(skip_all, fields(identifier))]
pub fn handle_delta_discovery_responses(
    identifier: String,
    stream: impl futures::Stream<Item = tonic::Result<DeltaDiscoveryResponse>> + 'static + Send,
    config: Arc<Config>,
    local: Arc<LocalVersions>,
    remote_addr: std::net::SocketAddr,
) -> std::pin::Pin<Box<dyn futures::Stream<Item = crate::Result<DeltaDiscoveryRequest>> + Send>> {
    Box::pin(async_stream::try_stream! {
        let _stream_metrics = metrics::StreamConnectionMetrics::new(identifier.clone());
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

            metrics::delta_discovery_responses(control_plane_identifier, &response.type_url).inc();
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
                        Resource::try_from(res.resource.ok_or_else(|| eyre::format_err!("resource field not set"))?).map(|mut rsrc| {
                            rsrc.add_host_to_datacenter(remote_addr);
                            (rsrc, res.version)
                        })
                    }), response.removed_resources, &mut lock)
            };

            let error_detail = if let Err(error) = result {
                metrics::nacks(control_plane_identifier, &response.type_url).inc();
                Some(crate::generated::google::rpc::Status {
                    code: 3,
                    message: error.to_string(),
                    ..Default::default()
                })
            } else {
                metrics::acks(control_plane_identifier, &response.type_url).inc();
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
