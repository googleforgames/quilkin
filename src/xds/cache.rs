use cached::CachedAsync;
use tokio::sync::Mutex;

use crate::xds::{
    service::discovery::v3::DiscoveryResponse, DiscoveryServiceProvider, ResourceType,
};

const CACHE_LIFESPAN_IN_SECONDS: u64 = 5;

/// A generic [DiscoveryServiceProvider] cache, that will cache any matching
/// request from the underlying provider for a limited duration.
pub struct Cache {
    provider: Box<dyn DiscoveryServiceProvider>,
    cache: Mutex<cached::TimedCache<(String, u64, ResourceType), DiscoveryResponse>>,
}

impl Cache {
    pub fn new<P: DiscoveryServiceProvider + 'static>(provider: P) -> Self {
        Self {
            provider: Box::from(provider),
            cache: Mutex::new(cached::TimedCache::with_lifespan(CACHE_LIFESPAN_IN_SECONDS)),
        }
    }
}

#[tonic::async_trait]
impl crate::xds::DiscoveryServiceProvider for Cache {
    async fn discovery_request(
        &self,
        node_id: &str,
        version: u64,
        kind: ResourceType,
        names: &[String],
    ) -> Result<DiscoveryResponse, tonic::Status> {
        let mut lock = self.cache.lock().await;

        lock.try_get_or_set_with((node_id.to_owned(), version, kind), || {
            self.provider
                .discovery_request(node_id, version, kind, names)
        })
        .await
        .map(|response| response.clone())
    }
}
