use prost::Message;

use crate::xds::config::{
    cluster::v3::Cluster, endpoint::v3::ClusterLoadAssignment, listener::v3::Listener,
};

macro_rules! type_urls {
     ($($base_url:literal : {$($const_name:ident = $type_url:literal),+ $(,)?})+) => {
         $(
             $(
                 const $const_name : &str = concat!($base_url, "/", $type_url);
             )+
         )+
     }
 }

type_urls! {
    "type.googleapis.com": {
        CLUSTER_TYPE = "envoy.config.cluster.v3.Cluster",
        ENDPOINT_TYPE = "envoy.config.endpoint.v3.ClusterLoadAssignment",
        EXTENSION_CONFIG_TYPE = "envoy.config.core.v3.TypedExtensionConfig",
        LISTENER_TYPE = "envoy.config.listener.v3.Listener",
        ROUTE_TYPE = "envoy.config.route.v3.RouteConfiguration",
        RUNTIME_TYPE = "envoy.service.runtime.v3.Runtime",
        SCOPED_ROUTE_TYPE = "envoy.config.route.v3.ScopedRouteConfiguration",
        SECRET_TYPE = "envoy.extensions.transport_sockets.tls.v3.Secret",
        VIRTUAL_HOST_TYPE = "envoy.config.route.v3.VirtualHost",
    }
}

#[derive(Clone, Debug)]
pub enum Resource {
    Cluster(Cluster),
    Endpoint(ClusterLoadAssignment),
    Listener(Listener),
}

impl Resource {
    pub fn name(&self) -> &str {
        match self {
            Self::Endpoint(endpoint) => &endpoint.cluster_name,
            Self::Cluster(cluster) => &cluster.name,
            Self::Listener(listener) => &listener.name,
        }
    }

    pub fn resource_type(&self) -> ResourceType {
        match self {
            Self::Cluster(_) => ResourceType::Cluster,
            Self::Endpoint(_) => ResourceType::Endpoint,
            Self::Listener(_) => ResourceType::Listener,
        }
    }
}

impl TryFrom<prost_types::Any> for Resource {
    type Error = eyre::Error;

    fn try_from(any: prost_types::Any) -> Result<Self, Self::Error> {
        Ok(match &*any.type_url {
            CLUSTER_TYPE => Resource::Cluster(<_>::decode(&*any.value)?),
            ENDPOINT_TYPE => Resource::Endpoint(<_>::decode(&*any.value)?),
            LISTENER_TYPE => Resource::Listener(<_>::decode(&*any.value)?),
            url => return Err(UnknownResourceType(url.into()).into()),
        })
    }
}

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
    pub const fn type_url(&self) -> &'static str {
        match self {
            Self::Cluster => CLUSTER_TYPE,
            Self::Endpoint => ENDPOINT_TYPE,
            Self::ExtensionConfig => EXTENSION_CONFIG_TYPE,
            Self::Listener => LISTENER_TYPE,
            Self::Route => ROUTE_TYPE,
            Self::Runtime => RUNTIME_TYPE,
            Self::ScopedRoute => SCOPED_ROUTE_TYPE,
            Self::Secret => SECRET_TYPE,
            Self::VirtualHost => VIRTUAL_HOST_TYPE,
        }
    }
}

impl TryFrom<&'_ str> for ResourceType {
    type Error = UnknownResourceType;

    fn try_from(url: &str) -> Result<Self, UnknownResourceType> {
        Ok(match url {
            CLUSTER_TYPE => Self::Cluster,
            ENDPOINT_TYPE => Self::Endpoint,
            EXTENSION_CONFIG_TYPE => Self::ExtensionConfig,
            LISTENER_TYPE => Self::Listener,
            ROUTE_TYPE => Self::Route,
            RUNTIME_TYPE => Self::Runtime,
            SCOPED_ROUTE_TYPE => Self::ScopedRoute,
            SECRET_TYPE => Self::Secret,
            VIRTUAL_HOST_TYPE => Self::VirtualHost,
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
