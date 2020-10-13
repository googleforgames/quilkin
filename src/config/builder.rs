use super::{Config, ConnectionConfig, Filter, Local};

/// Builder for a [`Config`]
#[derive(Debug)]
pub struct Builder {
    pub local: Local,
    pub filters: Vec<Filter>,
    pub connections: ConnectionConfig,
}

impl Builder {
    /// Returns a [`Builder`] with empty values.
    pub fn empty() -> Self {
        Builder {
            local: Local { port: 0 },
            filters: vec![],
            connections: ConnectionConfig::Server { endpoints: vec![] },
        }
    }

    pub fn with_local(self, local: Local) -> Self {
        Builder { local, ..self }
    }

    pub fn with_filters(self, filters: Vec<Filter>) -> Self {
        Builder { filters, ..self }
    }

    pub fn with_connections(self, connections: ConnectionConfig) -> Self {
        Builder {
            connections,
            ..self
        }
    }

    pub fn build(self) -> Config {
        Config {
            local: self.local,
            filters: self.filters,
            connections: self.connections,
            phantom: None,
        }
    }
}
