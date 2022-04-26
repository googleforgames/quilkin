/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// We don't control the codegen, so disable any code warnings in the
// proto modules.
#[allow(warnings)]
mod xds {
    pub mod core {
        pub mod v3 {
            #![doc(hidden)]
            tonic::include_proto!("xds.core.v3");
        }
    }

    pub mod r#type {
        pub mod matcher {
            pub mod v3 {
                pub use super::super::super::config::common::matcher::v3::*;
                tonic::include_proto!("envoy.r#type.matcher.v3");
            }
        }
        pub mod metadata {
            pub mod v3 {
                tonic::include_proto!("envoy.r#type.metadata.v3");
            }
        }
        pub mod tracing {
            pub mod v3 {
                tonic::include_proto!("envoy.r#type.tracing.v3");
            }
        }
        pub mod v3 {
            tonic::include_proto!("envoy.r#type.v3");
        }
    }
    pub mod config {
        pub mod accesslog {
            pub mod v3 {
                tonic::include_proto!("envoy.config.accesslog.v3");
            }
        }
        pub mod cluster {
            pub mod v3 {
                tonic::include_proto!("envoy.config.cluster.v3");
            }
        }
        pub mod common {
            pub mod matcher {
                pub mod v3 {
                    tonic::include_proto!("envoy.config.common.matcher.v3");
                }
            }
        }
        pub mod core {
            pub mod v3 {
                tonic::include_proto!("envoy.config.core.v3");
            }
        }
        pub mod endpoint {
            pub mod v3 {
                tonic::include_proto!("envoy.config.endpoint.v3");
            }
        }
        pub mod listener {
            pub mod v3 {
                tonic::include_proto!("envoy.config.listener.v3");
            }
        }
        pub mod route {
            pub mod v3 {
                tonic::include_proto!("envoy.config.route.v3");
            }
        }
    }
    pub mod service {
        pub mod discovery {
            pub mod v3 {
                tonic::include_proto!("envoy.service.discovery.v3");
            }
        }
        pub mod cluster {
            pub mod v3 {
                tonic::include_proto!("envoy.service.cluster.v3");
            }
        }
    }
}

#[allow(warnings)]
mod google {
    pub mod rpc {
        #![doc(hidden)]
        tonic::include_proto!("google.rpc");
    }
}

macro_rules! type_urls {
    ($($base_url:literal : {$($const_name:ident = $type_url:literal),+ $(,)?})+) => {
        $(
            $(
                pub const $const_name : &str = concat!($base_url, "/", $type_url);
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

pub(crate) mod ads_client;
mod cache;
pub(crate) mod cluster;
pub(crate) mod listener;
mod metrics;
pub mod provider;
mod resource;
pub(crate) mod server;

use crate::cluster::SharedCluster;
use crate::filters::SharedFilterChain;
use crate::proxy::{Admin as ProxyAdmin, Health};

pub(crate) use ads_client::AdsClient;
pub use cache::Cache;
pub use provider::DiscoveryServiceProvider;
pub use resource::ResourceType;
pub use server::ControlPlane;
pub use service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use tokio::sync::watch;
pub use xds::*;

use service::discovery::v3::aggregated_discovery_service_server::AggregatedDiscoveryServiceServer;

pub async fn manage(
    port: u16,
    admin_port: u16,
    provider: std::sync::Arc<dyn DiscoveryServiceProvider>,
) -> crate::Result<()> {
    // TODO: change this to receive config as param
    spawn_admin_server(admin_port)?;

    let server = AggregatedDiscoveryServiceServer::new(ControlPlane::from_arc(provider)?);
    let server = tonic::transport::Server::builder().add_service(server);
    Ok(server
        .serve((std::net::Ipv4Addr::UNSPECIFIED, port).into())
        .await?)
}

fn spawn_admin_server(admin_port: u16) -> crate::Result<()> {
    let health = Health::new();
    let admin = ProxyAdmin::new((std::net::Ipv4Addr::UNSPECIFIED, admin_port).into(), health);

    let cluster = SharedCluster::empty()?;
    let filter_chain = SharedFilterChain::empty();
    let (_tx, shutdown_rx) = watch::channel(());

    admin.run(cluster, filter_chain, shutdown_rx);
    Ok(())
}
