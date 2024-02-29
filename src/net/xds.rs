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
//#[allow(warnings)]
// mod xds {
//     pub mod core {
//         pub mod v3 {
//             #![doc(hidden)]
//             tonic::include_proto!("xds.core.v3");
//         }
//     }

//     pub mod r#type {
//         pub mod matcher {
//             pub mod v3 {
//                 pub use super::super::super::config::common::matcher::v3::*;
//                 tonic::include_proto!("envoy.r#type.matcher.v3");
//             }
//         }
//         pub mod metadata {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.r#type.metadata.v3");
//             }
//         }
//         pub mod tracing {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.r#type.tracing.v3");
//             }
//         }
//         pub mod v3 {
//             tonic::include_proto!("envoy.r#type.v3");
//         }
//     }
//     pub mod config {
//         pub mod accesslog {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.config.accesslog.v3");
//             }
//         }
//         pub mod cluster {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.config.cluster.v3");
//             }
//         }
//         pub mod common {
//             pub mod matcher {
//                 pub mod v3 {
//                     tonic::include_proto!("envoy.config.common.matcher.v3");
//                 }
//             }
//         }
//         pub mod core {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.config.core.v3");
//             }
//         }
//         pub mod endpoint {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.config.endpoint.v3");
//             }
//         }
//         pub mod listener {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.config.listener.v3");
//             }
//         }
//         pub mod route {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.config.route.v3");
//             }
//         }
//     }
//     pub mod service {
//         pub mod discovery {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.service.discovery.v3");
//             }
//         }
//         pub mod cluster {
//             pub mod v3 {
//                 tonic::include_proto!("envoy.service.cluster.v3");
//             }
//         }
//     }
// }

// use crate::generated::envoy;
// use crate::generated::xds;

pub(crate) use crate::generated::quilkin::relay::v1alpha1 as relay;

pub(crate) mod client;
pub(crate) mod metrics;
mod resource;
pub(crate) mod server;

use crate::net::{cluster::EndpointSetVersion, endpoint::Locality};

pub use crate::generated::envoy::{
    config::core::v3::{self as core, socket_address},
    config::listener::v3 as listener,
    service::discovery::v3 as discovery,
};
pub use client::{AdsClient, Client};
pub use resource::{Resource, ResourceType};
// pub use self::{
//     client::{AdsClient, Client},
//     envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient,
//     envoy::*,
//     resource::{Resource, ResourceType},
//     server::ControlPlane,
//     xds::*,
// };
use std::collections::HashMap;

/// Keeps track of what resource versions a particular client has
pub enum ClientVersions {
    Listener,
    Cluster(HashMap<Option<Locality>, EndpointSetVersion>),
    Datacenter,
}

/// The resources and versions that were sent in a delta response, when acked
/// this is used with `ClientVersions::ack` to update the set of resources on
/// the client has
pub enum AwaitingAck {
    Listener,
    Cluster {
        updated: Vec<(Option<Locality>, EndpointSetVersion)>,
        remove_none: bool,
    },
    Datacenter,
}

impl ClientVersions {
    #[inline]
    pub fn new(rt: ResourceType) -> Self {
        match rt {
            ResourceType::Listener => Self::Listener,
            ResourceType::Cluster => Self::Cluster(HashMap::new()),
            ResourceType::Datacenter => Self::Datacenter,
        }
    }

    #[inline]
    pub fn typ(&self) -> ResourceType {
        match self {
            Self::Listener => ResourceType::Listener,
            Self::Cluster(_) => ResourceType::Cluster,
            Self::Datacenter => ResourceType::Datacenter,
        }
    }

    /// Updates the versions of the client following an `ACK` by the client for
    /// a set of resources
    #[inline]
    pub fn ack(&mut self, ack: AwaitingAck) {
        match (self, ack) {
            (Self::Listener, AwaitingAck::Listener)
            | (Self::Datacenter, AwaitingAck::Datacenter) => {}
            (
                Self::Cluster(map),
                AwaitingAck::Cluster {
                    updated,
                    remove_none,
                },
            ) => {
                for (locality, version) in updated {
                    map.insert(locality, version);
                }

                if remove_none {
                    map.remove(&None);
                }
            }
            _ => unreachable!("acking the wrong resource type"),
        }
    }

    #[inline]
    pub fn remove(&mut self, name: String) {
        match self {
            Self::Listener | Self::Datacenter => {}
            Self::Cluster(map) => {
                let locality = if name.is_empty() {
                    None
                } else {
                    match name.parse() {
                        Ok(l) => Some(l),
                        Err(err) => {
                            tracing::error!(error = %err, name, "Failed to parse locality");
                            return;
                        }
                    }
                };
                map.remove(&locality);
            }
        }
    }

    /// Resets the client versions to those specified by the client itself
    #[inline]
    pub fn reset(&mut self, versions: HashMap<String, String>) -> crate::Result<()> {
        match self {
            Self::Listener | Self::Datacenter => Ok(()),
            Self::Cluster(map) => {
                map.clear();

                for (k, v) in versions {
                    let locality = if k.is_empty() { None } else { Some(k.parse()?) };
                    let version = v.parse()?;

                    map.insert(locality, version);
                }

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::test::AddressType;
    use crate::{config::Config, filters::*, net::endpoint::Endpoint};

    #[tokio::test]
    async fn token_routing() {
        let mut helper = crate::test::TestHelper::default();
        let token = "mytoken";
        let address = {
            let mut addr = Endpoint::new(helper.run_echo_server(&AddressType::Ipv6).await);
            addr.metadata.known.tokens.insert(token.into());
            crate::test::map_to_localhost(&mut addr.address).await;
            addr
        };
        let clusters = crate::net::cluster::ClusterMap::default();

        tracing::debug!(?address);
        clusters.insert_default([address].into());
        tracing::debug!(?clusters);

        let xds_port = crate::test::available_addr(&AddressType::Random)
            .await
            .port();
        let xds_config: Arc<crate::Config> = serde_json::from_value(serde_json::json!({
            "version": "v1alpha1",
            "id": "test-proxy",
            "clusters": clusters,
        }))
        .map(Arc::new)
        .unwrap();

        let client_addr = crate::test::available_addr(&AddressType::Random).await;
        let client_config = serde_json::from_value(serde_json::json!({
            "version": "v1alpha1",
            "id": "test-proxy",
        }))
        .map(Arc::new)
        .unwrap();

        // Test that the client can handle the manager dropping out.
        let manage_admin = crate::cli::Admin::Manage(<_>::default());
        let handle = tokio::spawn(server::spawn(
            xds_port,
            manage_admin.clone(),
            xds_config.clone(),
        ));

        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(crate::ShutdownKind::Testing);
        tokio::spawn(server::spawn(
            xds_port,
            manage_admin.clone(),
            xds_config.clone(),
        ));
        let client_proxy = crate::cli::Proxy {
            port: client_addr.port(),
            management_server: vec![format!("http://[::1]:{}", xds_port).parse().unwrap()],
            ..<_>::default()
        };

        let proxy_admin = crate::cli::Admin::Proxy(<_>::default());
        tokio::spawn(async move {
            client_proxy
                .run(client_config, proxy_admin, None, shutdown_rx)
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handle.abort();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tokio::spawn(server::spawn(xds_port, manage_admin, xds_config.clone()));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        const VERSION_KEY: &str = "quilkin.dev/load_balancer/version";
        const TOKEN_KEY: &str = "quilkin.dev/load_balancer/token";

        xds_config.filters.store(Arc::new(
            FilterChain::try_create([
                Capture::as_filter_config(capture::Config {
                    metadata_key: VERSION_KEY.into(),
                    strategy: capture::Suffix {
                        size: 1,
                        remove: true,
                    }
                    .into(),
                })
                .unwrap(),
                Match::as_filter_config(r#match::Config {
                    on_write: None,
                    on_read: Some(r#match::DirectionalConfig {
                        metadata_key: VERSION_KEY.into(),
                        branches: vec![r#match::Branch {
                            value: 1.into(),
                            filter: Capture::as_filter_config(capture::Config {
                                metadata_key: TOKEN_KEY.into(),
                                strategy: capture::Suffix {
                                    size: 16,
                                    remove: true,
                                }
                                .into(),
                            })
                            .unwrap(),
                        }],
                        fallthrough: <_>::default(),
                    }),
                })
                .unwrap(),
                Match::as_filter_config(r#match::Config {
                    on_write: None,
                    on_read: Some(r#match::DirectionalConfig {
                        metadata_key: VERSION_KEY.into(),
                        branches: vec![r#match::Branch {
                            value: 1.into(),
                            filter: TokenRouter::as_filter_config(token_router::Config {
                                metadata_key: TOKEN_KEY.into(),
                            })
                            .unwrap(),
                        }],
                        fallthrough: <_>::default(),
                    }),
                })
                .unwrap(),
            ])
            .unwrap(),
        ));

        let fixture = "Hello World!";
        let data = fixture.as_bytes();
        let mut packet = data.to_vec();
        packet.extend(token.as_bytes());

        let client = helper.open_socket_and_recv_single_packet().await;

        client
            .socket
            .send_to(&packet, (std::net::Ipv6Addr::LOCALHOST, client_addr.port()))
            .await
            .unwrap();
        let response =
            tokio::time::timeout(std::time::Duration::from_millis(100), client.packet_rx)
                .await
                .unwrap()
                .unwrap();

        assert_eq!(format!("{}{}", fixture, token), response);
    }

    #[tokio::test]
    async fn basic() {
        let config: Arc<Config> = serde_json::from_value(serde_json::json!({
            "version": "v1alpha1",
            "id": "test-proxy",
        }))
        .map(Arc::new)
        .unwrap();

        let proxy_mode = crate::cli::Admin::Proxy(<_>::default());
        tokio::spawn(server::spawn(23456, proxy_mode.clone(), config.clone()));
        let client = Client::connect(
            "test-client".into(),
            proxy_mode,
            vec!["http://127.0.0.1:23456".try_into().unwrap()],
        )
        .await
        .unwrap();
        let mut stream =
            client.xds_client_stream(config.clone(), crate::cli::admin::IDLE_REQUEST_INTERVAL);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Each time, we create a new upstream endpoint and send a cluster update for it.
        let concat_bytes = vec![("b", "c,"), ("d", "e")];
        for (b1, b2) in concat_bytes.into_iter() {
            let socket = std::net::UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)).unwrap();
            let local_addr: crate::net::endpoint::EndpointAddress =
                socket.local_addr().unwrap().into();

            config.clusters.modify(|clusters| {
                clusters.insert(
                    None,
                    Some(Endpoint::new(local_addr.clone()))
                        .into_iter()
                        .collect(),
                );
            });

            let filters = FilterChain::try_create([
                Concatenate::as_filter_config(concatenate::Config {
                    on_read: concatenate::Strategy::Append,
                    on_write: <_>::default(),
                    bytes: b1.as_bytes().to_vec(),
                })
                .unwrap(),
                Concatenate::as_filter_config(concatenate::Config {
                    on_read: concatenate::Strategy::Append,
                    on_write: <_>::default(),
                    bytes: b2.as_bytes().to_vec(),
                })
                .unwrap(),
            ])
            .unwrap();

            config.filters.modify(|chain| *chain = filters.clone());

            stream
                .aggregated_subscribe(ResourceType::Cluster, &[])
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert_eq!(
                local_addr,
                config
                    .clusters
                    .read()
                    .get_default()
                    .unwrap()
                    .endpoints
                    .iter()
                    .next()
                    .unwrap()
                    .address
            );

            stream
                .aggregated_subscribe(ResourceType::Listener, &[])
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let changed_filters = config.filters.load();

            assert_eq!(changed_filters.len(), 2);

            let mut iter = changed_filters.iter();
            assert_eq!(iter.next().unwrap(), filters[0].clone().into());
            assert_eq!(iter.next().unwrap(), filters[1].clone().into());
        }
    }
}
