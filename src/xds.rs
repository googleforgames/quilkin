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

                impl TryFrom<DiscoveryResponse> for DiscoveryRequest {
                    type Error = eyre::Error;

                    fn try_from(response: DiscoveryResponse) -> Result<Self, Self::Error> {
                        Ok(Self {
                            version_info: response.version_info,
                            resource_names: response
                                .resources
                                .into_iter()
                                .map(crate::xds::Resource::try_from)
                                .map(|result| result.map(|resource| resource.name().to_owned()))
                                .collect::<Result<Vec<_>, _>>()?,
                            type_url: response.type_url,
                            response_nonce: response.nonce,
                            ..<_>::default()
                        })
                    }
                }
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
        tonic::include_proto!("google.rpc");
    }
}

pub(crate) mod client;
mod metrics;
mod resource;
pub(crate) mod server;

use service::discovery::v3::aggregated_discovery_service_server::AggregatedDiscoveryServiceServer;

pub use client::Client;
pub use resource::{Resource, ResourceType};
pub use server::ControlPlane;
pub use service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
pub use xds::*;

#[tracing::instrument(skip_all)]
pub async fn manage(config: std::sync::Arc<crate::Config>) -> crate::Result<()> {
    let port = config.proxy.load().port;

    let server = AggregatedDiscoveryServiceServer::new(ControlPlane::from_arc(config));
    let server = tonic::transport::Server::builder().add_service(server);
    tracing::info!("Serving management server at {}", port);
    Ok(server
        .serve((std::net::Ipv4Addr::UNSPECIFIED, port).into())
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use crate::{config::Config, endpoint::Endpoint, filters::*};

    #[tokio::test]
    async fn token_routing() {
        let mut helper = crate::test_utils::TestHelper::default();
        let token = uuid::Uuid::new_v4().into_bytes();
        let address = {
            let mut addr = Endpoint::new(helper.run_echo_server().await);
            addr.metadata.known.tokens.insert(token.into());
            addr
        };
        let localities = crate::endpoint::LocalityEndpoints::from(address.clone());

        let xds_port = crate::test_utils::available_addr().await.port();
        let xds_config: Config = serde_json::from_value(serde_json::json!({
            "admin": null,
            "version": "v1alpha1",
            "proxy": {
                "id": "test-proxy",
                "port": xds_port
            },
            "clusters": {
                "default": {
                    "localities": [localities]
                }
            },
        }))
        .unwrap();

        let client_addr = crate::test_utils::available_addr().await;
        let client_config: Config = serde_json::from_value(serde_json::json!({
            "version": "v1alpha1",
            "admin": null,
            "proxy": {
                "id": "test-proxy",
                "port": client_addr.port(),
            },
            "management_servers": [{
                "address": format!("http://0.0.0.0:{}", xds_port),
            }]
        }))
        .unwrap();

        const VERSION_KEY: &str = "quilkin.dev/load_balancer/version";
        const TOKEN_KEY: &str = "quilkin.dev/load_balancer/token";

        xds_config.filters.store(Arc::new(
            [
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
            ]
            .try_into()
            .unwrap(),
        ));

        tokio::spawn(manage(Arc::new(xds_config)));
        tokio::spawn(crate::runner::run(client_config, []));
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

        let client = tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .await
            .unwrap();

        let data = "Hello World!".as_bytes();
        let mut packet = data.to_vec();
        packet.extend(token);
        packet.push(1);

        client
            .send_to(
                &packet,
                (std::net::Ipv4Addr::UNSPECIFIED, client_addr.port()),
            )
            .await
            .unwrap();
        let mut buf = vec![0; 12];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(data, buf);
    }

    #[tokio::test]
    async fn basic() {
        let config: Arc<Config> = serde_json::from_value(serde_json::json!({
            "version": "v1alpha1",
            "proxy": {
                "id": "test-proxy",
                "port": 23456u16,
            },
            "management_servers": [{
                "address": "http://127.0.0.1:23456",
            }]
        }))
        .map(Arc::new)
        .unwrap();

        let handle = tokio::spawn(manage(config.clone()));
        let client = Client::connect(config.clone()).await.unwrap();
        let mut stream = client.stream().await.unwrap();

        // Test that the client can handle the manager dropping out.
        handle.abort();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tokio::spawn(manage(config.clone()));

        // Each time, we create a new upstream endpoint and send a cluster update for it.
        let concat_bytes = vec![("b", "c,"), ("d", "e")];
        for (b1, b2) in concat_bytes.into_iter() {
            let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
            let local_addr: crate::endpoint::EndpointAddress = socket.local_addr().unwrap().into();

            config.clusters.modify(|clusters| {
                let cluster = clusters.default_cluster_mut();
                cluster.localities.clear();
                cluster.push(Endpoint::new(local_addr.clone()))
            });

            let filters = crate::filters::FilterChain::try_from(vec![
                ConcatenateBytes::as_filter_config(concatenate_bytes::Config {
                    on_read: concatenate_bytes::Strategy::Append,
                    on_write: <_>::default(),
                    bytes: b1.as_bytes().to_vec(),
                })
                .unwrap(),
                ConcatenateBytes::as_filter_config(concatenate_bytes::Config {
                    on_read: concatenate_bytes::Strategy::Append,
                    on_write: <_>::default(),
                    bytes: b2.as_bytes().to_vec(),
                })
                .unwrap(),
            ])
            .unwrap();

            config.filters.modify(|chain| *chain = filters.clone());

            stream.send(ResourceType::Cluster, &[]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            assert_eq!(
                local_addr,
                config
                    .clusters
                    .load()
                    .get_default()
                    .unwrap()
                    .endpoints()
                    .next()
                    .unwrap()
                    .address
            );

            stream.send(ResourceType::Listener, &[]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let changed_filters = config.filters.load();

            assert_eq!(changed_filters.len(), 2);

            let mut iter = changed_filters.iter();
            assert_eq!(iter.next().unwrap(), filters[0].clone().into());
            assert_eq!(iter.next().unwrap(), filters[1].clone().into());
        }
    }
}
