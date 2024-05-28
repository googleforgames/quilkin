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

pub mod client;
pub mod config;
pub mod locality;
pub mod metrics;
pub mod net;
pub mod resource;
pub mod server;

use crate::locality::Locality;

pub use crate::generated::envoy::{
    config::core::v3::{self as core, socket_address},
    config::listener::v3 as listener,
    service::discovery::v3 as discovery,
};
pub use client::{AdsClient, Client};
pub use quilkin_proto as generated;
pub use resource::{Resource, ResourceType};
use std::{collections::HashMap, fmt};

pub type Result<T, E = eyre::Error> = std::result::Result<T, E>;

/// Keeps track of what resource versions a particular client has
pub enum ClientVersions {
    Listener,
    FilterChain,
    Cluster(HashMap<Option<Locality>, EndpointSetVersion>),
    Datacenter,
}

/// The resources and versions that were sent in a delta response, when acked
/// this is used with `ClientVersions::ack` to update the set of resources on
/// the client has
pub enum AwaitingAck {
    Listener,
    FilterChain,
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
            ResourceType::FilterChain => Self::FilterChain,
            ResourceType::Cluster => Self::Cluster(HashMap::new()),
            ResourceType::Datacenter => Self::Datacenter,
        }
    }

    #[inline]
    pub fn typ(&self) -> ResourceType {
        match self {
            Self::Listener => ResourceType::Listener,
            Self::FilterChain => ResourceType::FilterChain,
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
            | (Self::Datacenter, AwaitingAck::Datacenter)
            | (Self::FilterChain, AwaitingAck::FilterChain) => {}
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
        let Self::Cluster(map) = self else {
            return;
        };

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

    /// Resets the client versions to those specified by the client itself
    #[inline]
    pub fn reset(&mut self, versions: HashMap<String, String>) -> crate::Result<()> {
        let Self::Cluster(map) = self else {
            return Ok(());
        };

        map.clear();

        for (k, v) in versions {
            let locality = if k.is_empty() { None } else { Some(k.parse()?) };
            let version = v.parse()?;

            map.insert(locality, version);
        }

        Ok(())
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct EndpointSetVersion(u64);

impl EndpointSetVersion {
    pub fn from_number(version: u64) -> Self {
        Self(version)
    }

    pub fn number(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for EndpointSetVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::Debug for EndpointSetVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl std::str::FromStr for EndpointSetVersion {
    type Err = eyre::Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(u64::from_str_radix(s, 16)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::test::AddressType;
    use crate::{
        config::Config,
        filters::*,
        net::{endpoint::Endpoint, TcpListener},
    };

    #[tokio::test]
    #[ignore = "flaky, ignoring for now"]
    async fn token_routing() {
        let mut helper = crate::test::TestHelper::default();
        let token = "mytoken";
        let address = {
            let mut addr = Endpoint::new(helper.run_echo_server(AddressType::Ipv6).await);
            addr.metadata.known.tokens.insert(token.into());
            crate::test::map_to_localhost(&mut addr.address).await;
            addr
        };
        let clusters = crate::net::cluster::ClusterMap::default();

        tracing::debug!(?address);
        clusters.insert_default([address].into());
        tracing::debug!(?clusters);

        let xds_config: Arc<crate::Config> = serde_json::from_value(serde_json::json!({
            "version": "v1alpha1",
            "id": "test-proxy",
            "clusters": clusters,
        }))
        .map(Arc::new)
        .unwrap();

        let client_addr = crate::test::available_addr(AddressType::Random).await;
        let client_config = serde_json::from_value(serde_json::json!({
            "version": "v1alpha1",
            "id": "test-proxy",
        }))
        .map(Arc::new)
        .unwrap();

        let xds_one = TcpListener::bind(None).unwrap();
        let xds_two = TcpListener::bind(None).unwrap();

        let xds_one_port = xds_one.port();
        let xds_two_port = xds_two.port();

        // Test that the client can handle the manager dropping out.
        let handle = tokio::spawn(
            server::ControlPlane::from_arc(
                xds_config.clone(),
                crate::components::admin::IDLE_REQUEST_INTERVAL,
            )
            .management_server(xds_one)
            .unwrap(),
        );

        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(crate::ShutdownKind::Testing);
        tokio::spawn(
            server::ControlPlane::from_arc(
                xds_config.clone(),
                crate::components::admin::IDLE_REQUEST_INTERVAL,
            )
            .management_server(xds_two)
            .unwrap(),
        );
        let client_proxy = crate::cli::Proxy {
            port: client_addr.port(),
            management_server: vec![
                format!("http://[::1]:{xds_one_port}").parse().unwrap(),
                format!("http://[::1]:{xds_two_port}").parse().unwrap(),
            ],
            qcmp_port: 0,
            ..<_>::default()
        };

        tokio::spawn(async move {
            client_proxy
                .run(client_config, Default::default(), None, shutdown_rx)
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        handle.abort();
        let _ = handle.await;

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

        let proxy_config = crate::components::proxy::Ready::default();
        let listener = TcpListener::bind(None).unwrap();
        let port = listener.port();
        tokio::spawn(
            crate::net::xds::server::ControlPlane::from_arc(
                config.clone(),
                proxy_config.idle_request_interval,
            )
            .management_server(listener)
            .unwrap(),
        );
        let client = Client::connect(
            "test-client".into(),
            vec![format!("http://127.0.0.1:{port}").try_into().unwrap()],
        )
        .await
        .unwrap();
        let mut stream = client.xds_client_stream(config.clone(), proxy_config);
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
