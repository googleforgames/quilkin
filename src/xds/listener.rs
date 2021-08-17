/*
 * Copyright 2021 Google LLC
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

use crate::filters::{
    manager::ListenerManagerArgs, CreateFilterArgs, FilterChain as ProxyFilterChain, FilterRegistry,
};
use crate::xds::envoy::config::listener::v3::{
    filter::ConfigType as LdsConfigType, FilterChain, Listener,
};
use crate::xds::envoy::service::discovery::v3::{DiscoveryRequest, DiscoveryResponse};
use crate::xds::error::Error;
use crate::xds::LISTENER_TYPE;

use std::sync::Arc;

use crate::xds::ads_client::send_discovery_req;
use bytes::Bytes;
use prometheus::Registry;
use prost::Message;
use slog::{debug, warn, Logger};
use tokio::sync::mpsc;

/// Tracks FilterChain resources on the LDS DiscoveryResponses and
/// instantiates a corresponding proxy filter chain and exposes it
/// to the caller whenever the filter chain changes.
pub(crate) struct ListenerManager {
    log: Logger,

    metrics_registry: Registry,

    // Registry to lookup filter factories by name.
    filter_registry: FilterRegistry,

    // Send discovery requests ACKs/NACKs to the server.
    discovery_req_tx: mpsc::Sender<DiscoveryRequest>,

    // Sends listener state updates to the caller.
    filter_chain_updates_tx: mpsc::Sender<Arc<ProxyFilterChain>>,
}

impl ListenerManager {
    pub(in crate::xds) fn new(
        log: Logger,
        args: ListenerManagerArgs,
        discovery_req_tx: mpsc::Sender<DiscoveryRequest>,
    ) -> Self {
        ListenerManager {
            log,
            metrics_registry: args.metrics_registry,
            filter_registry: args.filter_registry,
            discovery_req_tx,
            filter_chain_updates_tx: args.filter_chain_updates_tx,
        }
    }

    pub(in crate::xds) async fn on_listener_response(&mut self, response: DiscoveryResponse) {
        debug!(
            self.log,
            "{}: received response containing {} resource(s)",
            LISTENER_TYPE,
            response.resources.len()
        );

        let result = self
            .process_listener_response(response.resources)
            .await
            .map_err(|err| err.message);

        let error_message = match result {
            Ok(filter_chain) => {
                self.filter_chain_updates_tx
                    .send(Arc::new(filter_chain))
                    .await
                    .map_err(|err| {
                        warn!(self.log, "Failed to send filter chain update on channel");
                        err
                    })
                    // ok is safe here because an error can only be due to the consumer dropping
                    // the receiving side and we can't do much about that since it could mean
                    // that they're no longer interested or we're shutting down.
                    .ok();

                None
            }
            Err(message) => Some(message),
        };

        self.send_discovery_req(
            LISTENER_TYPE,
            response.version_info,
            response.nonce,
            error_message,
            vec![], // LDS uses a wildcard request.
        )
        .await;
    }

    async fn process_listener_response(
        &mut self,
        mut resources: Vec<prost_types::Any>,
    ) -> Result<ProxyFilterChain, Error> {
        let resource = match resources.len() {
            0 => return Ok(ProxyFilterChain::new(vec![], &self.metrics_registry)?),
            1 => resources.swap_remove(0),
            n => {
                return Err(Error::new(format!(
                    "at most 1 listener can be specified: got {}",
                    n
                )))
            }
        };

        let mut listener = Listener::decode(Bytes::from(resource.value))
            .map_err(|err| Error::new(format!("listener decode error: {}", err.to_string())))?;

        let lds_filter_chain = match listener.filter_chains.len() {
            0 => return Ok(ProxyFilterChain::new(vec![], &self.metrics_registry)?),
            1 => listener.filter_chains.swap_remove(0),
            n => {
                return Err(Error::new(format!(
                    "at most 1 filter chain can be provided: got {}",
                    n
                )))
            }
        };

        self.process_filter_chain(lds_filter_chain)
    }

    fn process_filter_chain(
        &self,
        lds_filter_chain: FilterChain,
    ) -> Result<ProxyFilterChain, Error> {
        let mut filters = vec![];
        for filter in lds_filter_chain.filters {
            let config = filter
                .config_type
                .map(|config| match config {
                    LdsConfigType::TypedConfig(config) => Ok(config),
                    invalid => Err(Error::new(format!(
                        "unsupported filter.config_type: {:?}",
                        invalid
                    ))),
                })
                .transpose()?;
            let create_filter_args =
                CreateFilterArgs::dynamic(self.metrics_registry.clone(), config);

            let name = filter.name;
            let filter = self
                .filter_registry
                .get(&name, create_filter_args)
                .map_err(|err| Error::new(format!("{}", err)))?;

            filters.push((name, filter));
        }

        Ok(ProxyFilterChain::new(filters, &self.metrics_registry)?)
    }

    // Send a DiscoveryRequest ACK/NACK back to the server for the given version and nonce.
    async fn send_discovery_req(
        &mut self,
        type_url: &'static str,
        version_info: String,
        response_nonce: String,
        error_message: Option<String>,
        resource_names: Vec<String>,
    ) {
        send_discovery_req(
            self.log.clone(),
            type_url,
            version_info,
            response_nonce,
            error_message,
            resource_names,
            &mut self.discovery_req_tx,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::ListenerManager;
    use crate::filters::{manager::ListenerManagerArgs, prelude::*};
    use crate::test_utils::logger;
    use crate::xds::envoy::config::listener::v3::{
        filter::ConfigType, Filter as LdsFilter, FilterChain as LdsFilterChain, Listener,
    };
    use crate::xds::envoy::service::discovery::v3::{DiscoveryRequest, DiscoveryResponse};

    use std::time::Duration;

    use crate::endpoint::{Endpoint, Endpoints, UpstreamEndpoints};
    use crate::filters::{ConvertProtoConfigError, DynFilterFactory, FilterRegistry, FilterSet};
    use crate::xds::LISTENER_TYPE;
    use prometheus::Registry;
    use prost::Message;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;
    use tokio::sync::mpsc;
    use tokio::time;

    // A simple filter that will be used in the following tests.
    // It appends a string to each payload.
    const APPEND_TYPE_URL: &str = "filter.append";
    #[derive(Clone, PartialEq, Serialize, Deserialize)]
    pub struct Append {
        pub value: Option<prost::alloc::string::String>,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ProtoAppend {
        #[prost(message, optional, tag = "1")]
        pub value: Option<prost::alloc::string::String>,
    }
    impl TryFrom<ProtoAppend> for Append {
        type Error = ConvertProtoConfigError;
        fn try_from(p: ProtoAppend) -> std::result::Result<Self, Self::Error> {
            Ok(Self { value: p.value })
        }
    }

    impl Filter for Append {
        fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
            ctx.contents = format!(
                "{}{}",
                String::from_utf8(ctx.contents).unwrap(),
                self.value.as_ref().unwrap()
            )
            .into_bytes();
            Some(ctx.into())
        }
    }

    fn new_registry() -> FilterRegistry {
        FilterRegistry::new(FilterSet::with(std::array::IntoIter::new([
            DynFilterFactory::from(Box::from(AppendFactory)),
        ])))
    }

    struct AppendFactory;

    impl FilterFactory for AppendFactory {
        fn name(&self) -> &'static str {
            APPEND_TYPE_URL
        }

        fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
            let filter = args
                .config
                .map(|config| config.deserialize::<Append, ProtoAppend>(self.name()))
                .transpose()?
                .unwrap();
            if filter.value.as_ref().unwrap() == "reject" {
                Err(Error::FieldInvalid {
                    field: "value".into(),
                    reason: "reject requested".into(),
                })
            } else {
                Ok(Box::new(filter))
            }
        }
    }

    #[tokio::test]
    async fn listener_manager_create_filter_chain_from_lds_listener() {
        // Test that we can feed the manager a Listener resource containing
        // LDS filters and it can build up a filter chain from it.

        // Prepare a filter registry with the filter factories we need for the test.
        let filter_registry = new_registry();
        let (filter_chain_updates_tx, mut filter_chain_updates_rx) = mpsc::channel(10);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel(10);
        let mut manager = ListenerManager::new(
            logger(),
            ListenerManagerArgs::new(
                Registry::default(),
                filter_registry,
                filter_chain_updates_tx,
            ),
            discovery_req_tx,
        );

        // Create two LDS filters forming the filter chain.
        let filters = vec!["world", "!"]
            .into_iter()
            .map(|value| LdsFilter {
                name: APPEND_TYPE_URL.into(),
                config_type: Some(ConfigType::TypedConfig({
                    let mut buf = vec![];
                    ProtoAppend {
                        value: Some(value.into()),
                    }
                    .encode(&mut buf)
                    .unwrap();
                    prost_types::Any {
                        type_url: APPEND_TYPE_URL.into(),
                        value: buf,
                    }
                })),
            })
            .collect();

        // Create Listener proto message.
        let lds_listener = create_lds_listener(
            "test-listener".into(),
            vec![create_lds_filter_chain(filters)],
        );

        let mut buf = vec![];
        lds_listener.encode(&mut buf).unwrap();
        let lds_resource = prost_types::Any {
            type_url: LISTENER_TYPE.into(),
            value: buf,
        };

        // Send the proto message as a DiscoveryResponse to the manager.
        manager
            .on_listener_response(DiscoveryResponse {
                version_info: "test-version".into(),
                resources: vec![lds_resource],
                canary: false,
                type_url: LISTENER_TYPE.into(),
                nonce: "test-nonce".into(),
                control_plane: None,
            })
            .await;

        // Expect an ACK DiscoveryRequest from the manager.
        let discovery_req = time::timeout(Duration::from_secs(5), discovery_req_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            DiscoveryRequest {
                version_info: "test-version".into(),
                response_nonce: "test-nonce".into(),
                type_url: LISTENER_TYPE.into(),
                resource_names: vec![],
                node: None,
                error_detail: None,
            },
            discovery_req,
        );

        // Expect a filter chain update from the manager.
        let filter_chain = time::timeout(Duration::from_secs(5), filter_chain_updates_rx.recv())
            .await
            .unwrap()
            .unwrap();

        // Test the new filter chain's functionality. It should append to payloads.
        let response = filter_chain
            .read(ReadContext::new(
                UpstreamEndpoints::from(
                    Endpoints::new(vec![Endpoint::new("127.0.0.1:8080".parse().unwrap())]).unwrap(),
                ),
                "127.0.0.1:8081".parse().unwrap(),
                "hello-".into(),
            ))
            .unwrap();

        assert_eq!(
            "hello-world!",
            String::from_utf8(response.contents).unwrap()
        );
    }

    #[tokio::test]
    async fn listener_manager_create_empty_filter_chain() {
        // Test that we send an empty filter chain update if the LDS Listener resource feed the manager a Listener resource containing
        // contains no filter chain.

        // Prepare a filter registry with the filter factories we need for the test.
        let filter_registry = new_registry();
        let (filter_chain_updates_tx, mut filter_chain_updates_rx) = mpsc::channel(10);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel(10);
        let mut manager = ListenerManager::new(
            logger(),
            ListenerManagerArgs::new(
                Registry::default(),
                filter_registry,
                filter_chain_updates_tx,
            ),
            discovery_req_tx,
        );

        let test_cases = vec![
            (
                vec![LdsFilter {
                    name: APPEND_TYPE_URL.into(),
                    config_type: Some(ConfigType::TypedConfig({
                        let mut buf = vec![];
                        ProtoAppend {
                            value: Some("world".into()),
                        }
                        .encode(&mut buf)
                        .unwrap();
                        prost_types::Any {
                            type_url: APPEND_TYPE_URL.into(),
                            value: buf,
                        }
                    })),
                }],
                "hello-world",
            ),
            (vec![], "hello-"),
        ];

        for (i, (filter, expected_payload)) in test_cases.into_iter().enumerate() {
            // Send a response with a filter chain.
            let lds_listener = create_lds_listener(
                format!("test-listener-{}", i),
                vec![create_lds_filter_chain(filter)],
            );
            let mut buf = vec![];
            lds_listener.encode(&mut buf).unwrap();
            let lds_resource = prost_types::Any {
                type_url: LISTENER_TYPE.into(),
                value: buf,
            };

            let (version_info, nonce) = (format!("version-{}", i), format!("nonce-{}", i));
            // Send the proto message as a DiscoveryResponse to the manager.
            manager
                .on_listener_response(DiscoveryResponse {
                    version_info: version_info.clone(),
                    resources: vec![lds_resource],
                    canary: false,
                    type_url: LISTENER_TYPE.into(),
                    nonce: nonce.clone(),
                    control_plane: None,
                })
                .await;

            // Expect an ACK DiscoveryRequest from the manager.
            let discovery_req = time::timeout(Duration::from_secs(5), discovery_req_rx.recv())
                .await
                .unwrap()
                .unwrap();

            assert_eq!(
                DiscoveryRequest {
                    version_info,
                    response_nonce: nonce,
                    type_url: LISTENER_TYPE.into(),
                    resource_names: vec![],
                    node: None,
                    error_detail: None,
                },
                discovery_req,
            );

            // Expect a filter chain update from the manager.
            let filter_chain =
                time::timeout(Duration::from_secs(5), filter_chain_updates_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();

            // Test the new filter chain's functionality.
            let response = filter_chain
                .read(ReadContext::new(
                    UpstreamEndpoints::from(
                        Endpoints::new(vec![Endpoint::new("127.0.0.1:8080".parse().unwrap())])
                            .unwrap(),
                    ),
                    "127.0.0.1:8081".parse().unwrap(),
                    "hello-".into(),
                ))
                .unwrap();

            assert_eq!(
                expected_payload,
                String::from_utf8(response.contents).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn listener_manager_reject_updates() {
        // Test that the manager returns NACK DiscoveryRequests for updates it failed to process.

        let filter_registry = new_registry();
        let (filter_chain_updates_tx, _filter_chain_updates_rx) = mpsc::channel(10);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel(10);
        let mut manager = ListenerManager::new(
            logger(),
            ListenerManagerArgs::new(
                Registry::default(),
                filter_registry,
                filter_chain_updates_tx,
            ),
            discovery_req_tx,
        );

        let test_cases = vec![
            (
                // The filter is explicitly configured to reject
                // config with this value.
                vec![create_lds_filter_chain(vec![LdsFilter {
                    name: APPEND_TYPE_URL.into(),
                    config_type: Some(ConfigType::TypedConfig({
                        let mut buf = vec![];
                        ProtoAppend {
                            value: Some("reject".into()),
                        }
                        .encode(&mut buf)
                        .unwrap();
                        prost_types::Any {
                            type_url: APPEND_TYPE_URL.into(),
                            value: buf,
                        }
                    })),
                }])],
                "reject requested",
            ),
            (
                // Filter does not exist in the filter registry.
                vec![create_lds_filter_chain(vec![LdsFilter {
                    name: "MissingFilter".into(),
                    config_type: Some(ConfigType::TypedConfig(prost_types::Any {
                        type_url: "MissingFilter".into(),
                        value: vec![],
                    })),
                }])],
                "filter `MissingFilter` not found",
            ),
            (
                // Multiple filter chains.
                (0..2)
                    .into_iter()
                    .map(|_| {
                        create_lds_filter_chain(vec![LdsFilter {
                            name: "MissingFilter".into(),
                            config_type: Some(ConfigType::TypedConfig(prost_types::Any {
                                type_url: "MissingFilter".into(),
                                value: vec![],
                            })),
                        }])
                    })
                    .collect(),
                "at most 1 filter chain can be provided: got 2",
            ),
        ];
        for (filter_chains, error_message) in test_cases {
            let lds_listener = create_lds_listener("test-listener".into(), filter_chains);

            let mut buf = vec![];
            lds_listener.encode(&mut buf).unwrap();
            let lds_resource = prost_types::Any {
                type_url: LISTENER_TYPE.into(),
                value: buf,
            };

            manager
                .on_listener_response(DiscoveryResponse {
                    version_info: "test-version".into(),
                    resources: vec![lds_resource],
                    canary: false,
                    type_url: LISTENER_TYPE.into(),
                    nonce: "test-nonce".into(),
                    control_plane: None,
                })
                .await;

            let mut discovery_req = time::timeout(Duration::from_secs(5), discovery_req_rx.recv())
                .await
                .unwrap()
                .unwrap();

            let error_detail = discovery_req.error_detail.take().expect("expected error");
            assert_eq!(
                DiscoveryRequest {
                    version_info: "test-version".into(),
                    response_nonce: "test-nonce".into(),
                    type_url: LISTENER_TYPE.into(),
                    resource_names: vec![],
                    node: None,
                    error_detail: None,
                },
                discovery_req,
            );

            assert!(error_detail.message.contains(error_message));
        }
    }

    #[tokio::test]
    async fn listener_manager_reject_multiple_listeners() {
        // Test that the manager returns NACK DiscoveryRequests for updates with multiple listeners.

        let (filter_chain_updates_tx, _filter_chain_updates_rx) = mpsc::channel(10);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel(10);
        let mut manager = ListenerManager::new(
            logger(),
            ListenerManagerArgs::new(
                Registry::default(),
                FilterRegistry::new(FilterSet::default(&logger())),
                filter_chain_updates_tx,
            ),
            discovery_req_tx,
        );
        let lds_listener = create_lds_listener(
            "test-listener".into(),
            vec![create_lds_filter_chain(vec![LdsFilter {
                name: "MissingFilter".into(),
                config_type: Some(ConfigType::TypedConfig(prost_types::Any {
                    type_url: "MissingFilter".into(),
                    value: vec![],
                })),
            }])],
        );

        let mut buf = vec![];
        lds_listener.encode(&mut buf).unwrap();
        let lds_resource = prost_types::Any {
            type_url: LISTENER_TYPE.into(),
            value: buf,
        };

        manager
            .on_listener_response(DiscoveryResponse {
                version_info: "test-version".into(),
                resources: vec![lds_resource.clone(), lds_resource],
                canary: false,
                type_url: LISTENER_TYPE.into(),
                nonce: "test-nonce".into(),
                control_plane: None,
            })
            .await;

        let mut discovery_req = time::timeout(Duration::from_secs(5), discovery_req_rx.recv())
            .await
            .unwrap()
            .unwrap();

        let error_detail = discovery_req.error_detail.take().expect("expected error");
        assert_eq!(
            DiscoveryRequest {
                version_info: "test-version".into(),
                response_nonce: "test-nonce".into(),
                type_url: LISTENER_TYPE.into(),
                resource_names: vec![],
                node: None,
                error_detail: None,
            },
            discovery_req,
        );

        assert_eq!(
            error_detail.message,
            "at most 1 listener can be specified: got 2"
        );
    }

    #[allow(deprecated)]
    fn create_lds_filter_chain(filters: Vec<LdsFilter>) -> LdsFilterChain {
        LdsFilterChain {
            filter_chain_match: None,
            filters,
            use_proxy_proto: None,
            metadata: None,
            transport_socket: None,
            transport_socket_connect_timeout: None,
            name: "test-lds-filter-chain".into(),
            on_demand_configuration: None,
        }
    }

    #[allow(deprecated)]
    fn create_lds_listener(name: String, filter_chains: Vec<LdsFilterChain>) -> Listener {
        Listener {
            name,
            address: None,
            filter_chains,
            default_filter_chain: None,
            use_original_dst: None,
            per_connection_buffer_limit_bytes: None,
            metadata: None,
            deprecated_v1: None,
            drain_type: 0,
            listener_filters: vec![],
            listener_filters_timeout: None,
            continue_on_listener_filters_timeout: false,
            transparent: None,
            freebind: None,
            socket_options: vec![],
            tcp_fast_open_queue_length: None,
            traffic_direction: 0,
            udp_listener_config: None,
            api_listener: None,
            connection_balance_config: None,
            reuse_port: false,
            access_log: vec![],
            udp_writer_config: None,
            tcp_backlog_size: None,
            bind_to_port: None,
            listener_specifier: None,
        }
    }
}
