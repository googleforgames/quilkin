mod agones;
mod file;

pub use agones::AgonesProvider;
pub use file::FileProvider;

use crate::xds::{service::discovery::v3::DiscoveryResponse, ResourceType};

/// A trait over a discovery service provider responsible for returning
/// the [DiscoveryResponse]s. The type of resource returned is based on the [ResourceType].
#[tonic::async_trait]
pub trait DiscoveryServiceProvider: Send + Sync {
    async fn discovery_request(
        &self,
        node_id: &str,
        version: u64,
        kind: ResourceType,
        names: &[String],
    ) -> Result<DiscoveryResponse, tonic::Status>;
}
