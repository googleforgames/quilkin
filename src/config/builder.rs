use super::{Config, Filter};
use crate::config::{EndPoint, Proxy, ProxyMode, Source, Version};

/// Builder for a [`Config`]
#[derive(Debug)]
pub struct Builder {
    pub mode: ProxyMode,
    pub port: u16,
    pub source: Source,
}

impl Builder {
    /// Returns a [`Builder`] with empty values.
    pub fn empty() -> Self {
        Builder {
            mode: ProxyMode::Server,
            port: 0,
            source: Source::Static {
                filters: vec![],
                endpoints: vec![],
            },
        }
    }

    pub fn with_mode(self, mode: ProxyMode) -> Self {
        Builder { mode, ..self }
    }

    pub fn with_port(self, port: u16) -> Self {
        Builder { port, ..self }
    }

    pub fn with_static(self, filters: Vec<Filter>, endpoints: Vec<EndPoint>) -> Self {
        let source = Source::Static { filters, endpoints };
        Builder { source, ..self }
    }

    pub fn build(self) -> Config {
        Config {
            version: Version::V1Alpha1,
            proxy: Proxy {
                mode: self.mode,
                id: "test".into(),
                port: self.port,
            },
            admin: None,
            source: self.source,
            phantom: None,
        }
    }
}
