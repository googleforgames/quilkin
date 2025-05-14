use crate::filters::{CreationError, FilterChain, FilterInstance};
use std::sync::Arc;

/// The `ProxyFilterChain` is used when the UDP service is enabled.
///
/// For the UDP service, we don't need notification capabilities when modifying
/// the filter chain, rather each loop just reads the cached value, unless the
/// filter has been changed, an extremely rare occurance, and reloads the value
#[derive(Clone, Debug)]
pub struct ProxyFilterChain {
    chain: Arc<arc_swap::ArcSwap<FilterChain>>,
}

pub type CachedProxyFilterChain =
    arc_swap::Cache<Arc<arc_swap::ArcSwap<FilterChain>>, Arc<FilterChain>>;

impl ProxyFilterChain {
    /// Cached the filter chain, only reloading it if the filter changes
    #[inline]
    pub fn cached(&self) -> CachedProxyFilterChain {
        arc_swap::Cache::new(self.chain.clone())
    }

    #[inline]
    pub fn store(&self, new_chain: FilterChain) {
        self.chain.store(Arc::new(new_chain));
    }
}

impl Default for ProxyFilterChain {
    fn default() -> Self {
        Self {
            chain: Default::default(),
        }
    }
}

impl PartialEq for ProxyFilterChain {
    fn eq(&self, other: &Self) -> bool {
        &*self.chain.load() == &*other.chain.load()
    }
}

impl typemap_rev::TypeMapKey for ProxyFilterChain {
    type Value = ProxyFilterChain;
}

/// The `NotifyingFilterChain` broadcasts when a new `FilterChain` is stored
#[derive(Clone, Debug)]
pub struct NotifyingFilterChain {
    chain: Arc<parking_lot::Mutex<FilterChain>>,
    channel: tokio::sync::broadcast::Sender<()>,
}

impl NotifyingFilterChain {
    pub fn new() -> Self {
        Self {
            chain: Default::default(),
            channel: tokio::sync::broadcast::channel(1).0,
        }
    }

    #[inline]
    pub fn store(&self, new_chain: FilterChain) {
        {
            let mut cur = self.chain.lock();
            if *cur == new_chain {
                return;
            }

            *cur = new_chain;
        }

        tracing::debug!("sending new FilterChain notification");
        let _ = self.channel.send(());
    }

    #[inline]
    pub fn read(&self) -> parking_lot::MutexGuard<'_, FilterChain> {
        self.chain.lock()
    }
}

impl Default for NotifyingFilterChain {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for NotifyingFilterChain {
    fn eq(&self, other: &Self) -> bool {
        &*self.chain.lock() == &*other.chain.lock()
    }
}

impl typemap_rev::TypeMapKey for NotifyingFilterChain {
    type Value = NotifyingFilterChain;
}

#[derive(Clone, Debug)]
pub struct NotifyingProxyFilterChain {
    chain: Arc<arc_swap::ArcSwap<FilterChain>>,
    channel: tokio::sync::broadcast::Sender<()>,
}

impl NotifyingProxyFilterChain {
    pub fn new() -> Self {
        Self {
            chain: Default::default(),
            channel: tokio::sync::broadcast::channel(1).0,
        }
    }

    #[inline]
    pub fn store(&self, new_chain: FilterChain) {
        {
            let cur = self.chain.load();
            if (*cur).as_ref() == &new_chain {
                return;
            }
        }

        self.chain.store(Arc::new(new_chain));
        tracing::debug!("sending new FilterChain notification");
        let _ = self.channel.send(());
    }

    /// Cached the filter chain, only reloading it if the filter changes
    #[inline]
    pub fn cached(&self) -> CachedProxyFilterChain {
        arc_swap::Cache::new(self.chain.clone())
    }

    // #[inline]
    // pub fn read(&self) -> arc_swap::Guard<Arc<FilterChain>> {
    //     self.chain.load()
    // }
}

impl Default for NotifyingProxyFilterChain {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for NotifyingProxyFilterChain {
    fn eq(&self, other: &Self) -> bool {
        &*self.chain.load() == &*other.chain.load()
    }
}

impl typemap_rev::TypeMapKey for NotifyingProxyFilterChain {
    type Value = NotifyingProxyFilterChain;
}

#[derive(Clone, PartialEq)]
pub enum ConfigFilterChain {
    Proxy(ProxyFilterChain),
    Notifying(NotifyingFilterChain),
    NotifyingProxy(NotifyingProxyFilterChain),
}

impl ConfigFilterChain {
    #[inline]
    pub fn store(&self, new_chain: FilterChain) {
        match self {
            Self::Proxy(p) => p.store(new_chain),
            Self::Notifying(n) => n.store(new_chain),
            Self::NotifyingProxy(n) => n.store(new_chain),
        }
    }
}

impl serde::Serialize for ConfigFilterChain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Proxy(p) => p.chain.load().serialize(serializer),
            Self::Notifying(n) => n.chain.lock().serialize(serializer),
            Self::NotifyingProxy(n) => n.chain.load().serialize(serializer),
        }
    }
}

impl super::DynamicConfig {
    pub fn filters(&self) -> Option<ConfigFilterChain> {
        if let Some(pfc) = self.typemap.get::<ProxyFilterChain>() {
            Some(ConfigFilterChain::Proxy(pfc.clone()))
        } else if let Some(nfc) = self.typemap.get::<NotifyingFilterChain>() {
            Some(ConfigFilterChain::Notifying(nfc.clone()))
        } else if let Some(nfc) = self.typemap.get::<NotifyingProxyFilterChain>() {
            Some(ConfigFilterChain::NotifyingProxy(nfc.clone()))
        } else {
            None
        }
    }

    pub fn cached_proxy_filter_chain(&self) -> Option<CachedProxyFilterChain> {
        if let Some(pfc) = self.typemap.get::<ProxyFilterChain>() {
            Some(pfc.cached())
        } else if let Some(npfc) = self.typemap.get::<NotifyingProxyFilterChain>() {
            Some(npfc.cached())
        } else {
            None
        }
    }
}

/// Filter is the configuration for a single filter
#[derive(
    Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub name: String,
    pub label: Option<String>,
    pub config: Option<serde_json::Value>,
}

impl TryFrom<crate::net::cluster::proto::Filter> for Filter {
    type Error = CreationError;

    fn try_from(value: crate::net::cluster::proto::Filter) -> Result<Self, Self::Error> {
        let config = if let Some(cfg) = value.config {
            Some(
                serde_json::from_str(&cfg)
                    .map_err(|err| CreationError::DeserializeFailed(err.to_string()))?,
            )
        } else {
            None
        };

        Ok(Self {
            name: value.name,
            label: value.label,
            config,
        })
    }
}

impl From<(String, FilterInstance)> for Filter {
    fn from((name, instance): (String, FilterInstance)) -> Self {
        Self {
            name,
            label: instance.label().map(String::from),
            config: Some(serde_json::Value::clone(instance.config())),
        }
    }
}

use crate::generated::envoy::config::listener::v3 as listener;

impl TryFrom<listener::Filter> for Filter {
    type Error = CreationError;

    fn try_from(filter: listener::Filter) -> Result<Self, Self::Error> {
        use listener::filter::ConfigType;

        let config = if let Some(config_type) = filter.config_type {
            let config = match config_type {
                ConfigType::TypedConfig(any) => any,
                ConfigType::ConfigDiscovery(_) => {
                    return Err(CreationError::FieldInvalid {
                        field: "config_type".into(),
                        reason: "ConfigDiscovery is currently unsupported".into(),
                    });
                }
            };
            Some(
                crate::filters::FilterRegistry::get_factory(&filter.name)
                    .ok_or_else(|| CreationError::NotFound(filter.name.clone()))?
                    .encode_config_to_json(config)?,
            )
        } else {
            None
        };

        Ok(Self {
            name: filter.name,
            // TODO: keep the label across xDS
            label: None,
            config,
        })
    }
}

impl TryFrom<Filter> for listener::Filter {
    type Error = CreationError;

    fn try_from(filter: Filter) -> Result<Self, Self::Error> {
        use listener::filter::ConfigType;

        let config = if let Some(config) = filter.config {
            Some(
                crate::filters::FilterRegistry::get_factory(&filter.name)
                    .ok_or_else(|| CreationError::NotFound(filter.name.clone()))?
                    .encode_config_to_protobuf(config)?,
            )
        } else {
            None
        };

        Ok(Self {
            name: filter.name,
            config_type: config.map(ConfigType::TypedConfig),
        })
    }
}
