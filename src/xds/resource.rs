#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceType {
    Cluster,
    Endpoint,
    ExtensionConfig,
    Listener,
    Route,
    Runtime,
    ScopedRoute,
    Secret,
    VirtualHost,
}

impl ResourceType {
    /// Returns the corresponding type URL for the response type.
    pub fn type_url(&self) -> &'static str {
        match self {
            Self::Cluster => super::CLUSTER_TYPE,
            Self::Endpoint => super::ENDPOINT_TYPE,
            Self::ExtensionConfig => super::EXTENSION_CONFIG_TYPE,
            Self::Listener => super::LISTENER_TYPE,
            Self::Route => super::ROUTE_TYPE,
            Self::Runtime => super::RUNTIME_TYPE,
            Self::ScopedRoute => super::SCOPED_ROUTE_TYPE,
            Self::Secret => super::SECRET_TYPE,
            Self::VirtualHost => super::VIRTUAL_HOST_TYPE,
        }
    }
}

impl TryFrom<&'_ str> for ResourceType {
    type Error = UnknownResourceType;

    fn try_from(url: &str) -> Result<Self, UnknownResourceType> {
        Ok(match url {
            super::CLUSTER_TYPE => Self::Cluster,
            super::ENDPOINT_TYPE => Self::Endpoint,
            super::EXTENSION_CONFIG_TYPE => Self::ExtensionConfig,
            super::LISTENER_TYPE => Self::Listener,
            super::ROUTE_TYPE => Self::Route,
            super::RUNTIME_TYPE => Self::Runtime,
            super::SCOPED_ROUTE_TYPE => Self::ScopedRoute,
            super::SECRET_TYPE => Self::Secret,
            super::VIRTUAL_HOST_TYPE => Self::VirtualHost,
            unknown => return Err(UnknownResourceType(unknown.to_owned())),
        })
    }
}

impl TryFrom<String> for ResourceType {
    type Error = UnknownResourceType;

    fn try_from(url: String) -> Result<Self, UnknownResourceType> {
        Self::try_from(&*url)
    }
}

impl TryFrom<&'_ String> for ResourceType {
    type Error = UnknownResourceType;

    fn try_from(url: &String) -> Result<Self, UnknownResourceType> {
        Self::try_from(&**url)
    }
}

/// Error indicating an unknown resource type was found.
#[derive(Debug, thiserror::Error)]
#[error("Unknown resource type: {0}")]
pub struct UnknownResourceType(String);

impl From<UnknownResourceType> for tonic::Status {
    fn from(error: UnknownResourceType) -> Self {
        tonic::Status::invalid_argument(error.to_string())
    }
}
