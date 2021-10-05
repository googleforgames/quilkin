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
    manager::ListenerManagerArgs, CreateFilterArgs, FilterChain as ProxyFilterChain,
    FilterChainSource, FilterRegistry,
};
use crate::xds::envoy::config::listener::v3::{
    filter::ConfigType as LdsConfigType, Filter, FilterChain, Listener,
};
use crate::xds::envoy::service::discovery::v3::{DiscoveryRequest, DiscoveryResponse};
use crate::xds::error::Error;
use crate::xds::LISTENER_TYPE;

use std::sync::Arc;

use crate::config::{CaptureVersion, ValidateFilterChainVersions};
use crate::endpoint::base64_set;
use crate::filters::chain::Version as FilterChainVersion;
use crate::xds::ads_client::send_discovery_req;
use bytes::Bytes;
use prometheus::Registry;
use prost::Message;
use slog::{debug, warn, Logger};
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Tracks FilterChain resources on the LDS DiscoveryResponses and
/// instantiates a corresponding proxy filter chain and exposes it
/// to the caller whenever the filter chain changes.
pub(crate) struct ListenerManager {
    log: Logger,

    metrics_registry: Registry,

    capture_version: Option<CaptureVersion>,

    // Registry to lookup filter factories by name.
    filter_registry: FilterRegistry,

    // Send discovery requests ACKs/NACKs to the server.
    discovery_req_tx: mpsc::Sender<DiscoveryRequest>,

    // Sends listener state updates to the caller.
    filter_chain_updates_tx: mpsc::Sender<Arc<FilterChainSource>>,
}

/// An error returned while processing a versioned filter chain resource.
struct ProcessVersionedFilterChainError {
    filter_chain_index: usize,
    message: String,
}

impl From<ProcessVersionedFilterChainError> for Error {
    fn from(err: ProcessVersionedFilterChainError) -> Self {
        Error::new(format!(
            "invalid FilterChain at index {}: {}",
            err.filter_chain_index, err.message
        ))
    }
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
            capture_version: args.capture_version,
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
            Ok(filter_chain_source) => {
                self.filter_chain_updates_tx
                    .send(filter_chain_source)
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

    // Returns an empty filter chain implementation.
    fn empty_filter_chain(&self) -> Result<Arc<FilterChainSource>, Error> {
        match self.capture_version.clone() {
            Some(capture_version) => Ok(FilterChainSource::versioned(
                capture_version,
                Default::default(),
            )),
            None => Ok(FilterChainSource::non_versioned(ProxyFilterChain::new(
                vec![],
                &self.metrics_registry,
            )?)),
        }
    }

    async fn process_listener_response(
        &mut self,
        mut resources: Vec<prost_types::Any>,
    ) -> Result<Arc<FilterChainSource>, Error> {
        let resource = match resources.len() {
            0 => return self.empty_filter_chain(),
            1 => resources.swap_remove(0),
            n => {
                return Err(Error::new(format!(
                    "at most 1 listener can be specified: got {}",
                    n
                )))
            }
        };

        let listener = Listener::decode(Bytes::from(resource.value))
            .map_err(|err| Error::new(format!("listener decode error: {}", err.to_string())))?;

        let mut lds_filter_chains = listener.filter_chains;
        if lds_filter_chains.is_empty() {
            return self.empty_filter_chain();
        }

        // If running with versioned filter chains, only accept filter chain
        // resources that include versions.
        match self.capture_version {
            Some(ref capture_version) => {
                self.process_versioned_filter_chain(capture_version.clone(), lds_filter_chains)
            }
            None => {
                if lds_filter_chains.len() != 1 {
                    return Err(Error::new(format!(
                        "at most 1 filter chain can be provided when using a non-versioned filter chain: got {}",
                        lds_filter_chains.len()
                    )));
                }

                self.process_filter_chain(lds_filter_chains.swap_remove(0).filters)
                    .map(FilterChainSource::non_versioned)
            }
        }
    }

    fn process_versioned_filter_chain(
        &self,
        capture_version: CaptureVersion,
        lds_filter_chains: Vec<FilterChain>,
    ) -> Result<Arc<FilterChainSource>, Error> {
        let mut filter_chains: HashMap<FilterChainVersion, Arc<ProxyFilterChain>> = HashMap::new();
        // Track version matches across all filter chains.
        let mut filter_chain_versions = Vec::<base64_set::Set>::new();

        for (i, lds_filter_chain) in lds_filter_chains.into_iter().enumerate() {
            // Get the versions handled by the filter chain.
            let versions: Vec<FilterChainVersion> = lds_filter_chain
                .filter_chain_match
                .map(|filter_chain_match| {
                    filter_chain_match
                        .application_protocols
                        .into_iter()
                        .enumerate()
                        .map(|(i, value)| {
                            base64::decode(&value)
                                .map(FilterChainVersion::from)
                                .map_err(|err| ProcessVersionedFilterChainError {
                                    filter_chain_index: i,
                                    message: format!(
                                        "version {} is not a valid base64 string: {:?}",
                                        value, err
                                    ),
                                })
                        })
                        .collect::<Result<_, _>>()
                })
                .transpose()?
                // Since we're running with versioned filter chains, each LDS FilterChain
                // resource must have a FilterChainMatch to match versions against.
                .ok_or_else(|| ProcessVersionedFilterChainError {
                    filter_chain_index: i,
                    message:
                        "no FilterChainMatch was provided while versioned filter chain is enabled"
                            .into(),
                })?;

            filter_chain_versions.push(
                versions
                    .iter()
                    .map(|version| version.as_ref())
                    .cloned()
                    .collect(),
            );

            let filter_chain = Arc::new(
                self.process_filter_chain(lds_filter_chain.filters)
                    .map_err(|err| ProcessVersionedFilterChainError {
                        filter_chain_index: i,
                        message: err.message,
                    })?,
            );

            for version in versions.into_iter() {
                filter_chains.insert(version, filter_chain.clone());
            }
        }

        // Validate versions across all filter chains.
        ValidateFilterChainVersions(filter_chain_versions.iter().collect())
            .validate()
            .map_err(|err| Error::new(format!("{}", err)))?;

        Ok(FilterChainSource::versioned(capture_version, filter_chains))
    }

    fn process_filter_chain(&self, lds_filters: Vec<Filter>) -> Result<ProxyFilterChain, Error> {
        let mut filters = vec![];
        for filter in lds_filters {
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
    use crate::filters::{manager::ListenerManagerArgs, prelude::*, FilterChainSource};
    use crate::test_utils::logger;
    use crate::xds::envoy::config::listener::v3::{
        filter::ConfigType, Filter as LdsFilter, FilterChain as LdsFilterChain, FilterChainMatch,
        Listener,
    };
    use crate::xds::envoy::service::discovery::v3::{DiscoveryRequest, DiscoveryResponse};

    use std::time::Duration;

    use crate::capture_bytes::Strategy;
    use crate::config::CaptureVersion;
    use crate::endpoint::{Endpoint, Endpoints, UpstreamEndpoints};
    use crate::filters::{ConvertProtoConfigError, DynFilterFactory, FilterRegistry, FilterSet};
    use crate::xds::LISTENER_TYPE;
    use prometheus::Registry;
    use prost::Message;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;
    use std::sync::Arc;
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

        fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
            let (config_json, filter) = args
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
                Ok(FilterInstance::new(
                    config_json,
                    Box::new(filter) as Box<dyn Filter>,
                ))
            }
        }
    }

    #[tokio::test]
    async fn listener_manager_create_filter_chain_from_lds_listener() {
        // Test that we can feed the manager a Listener resource containing
        // LDS filters and it can build up a filter chain from it.

        let (mut manager, mut filter_chain_updates_rx, mut discovery_req_rx) =
            create_listener_manager(None);

        // Create two LDS filters forming the filter chain.
        let lds_resource = create_lds_proto(
            "test",
            vec![create_lds_filter_chain(
                vec![
                    create_append_filter_proto("world"),
                    create_append_filter_proto("!"),
                ],
                None,
            )],
        );

        // Send the proto message as a DiscoveryResponse to the manager.
        manager
            .on_listener_response(create_discovery_response(
                "test-version",
                "test-nonce",
                lds_resource,
            ))
            .await;

        // Expect an ACK DiscoveryRequest from the manager.
        assert_discovery_request_ack(&mut discovery_req_rx, "test-version", "test-nonce").await;

        // Wait for a filter chain update from the manager.
        let filter_chain_source = wait_for_filter_chain_update(&mut filter_chain_updates_rx).await;

        // Test the new filter chain's functionality. It should append to payloads.
        let response = filter_chain_source
            .get_filter_chain_non_versioned()
            .unwrap()
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
    async fn listener_manager_create_versioned_filter_chains_from_lds_listener() {
        // Test that we can feed the manager a Listener resource containing
        // versioned LDS filters and it can build up versioned filter chains from it.

        let (mut manager, mut filter_chain_updates_rx, mut discovery_req_rx) =
            create_listener_manager(Some(CaptureVersion {
                strategy: Strategy::Prefix,
                size: 1,
                remove: true,
            }));

        // Send an update containing two LDS filter chains with different versioned.
        let lds_resource = create_lds_proto(
            "test",
            vec![
                create_lds_filter_chain(
                    vec![create_append_filter_proto("filter-0")],
                    with_versions(vec!["AA==".into(), "AQ==".into()]),
                ),
                create_lds_filter_chain(
                    vec![create_append_filter_proto("filter-1")],
                    with_versions(vec!["Ag==".into()]),
                ),
            ],
        );

        // Send the proto message as a DiscoveryResponse to the manager.
        manager
            .on_listener_response(create_discovery_response(
                "test-version",
                "test-nonce",
                lds_resource,
            ))
            .await;

        // Expect an ACK DiscoveryRequest from the manager.
        assert_discovery_request_ack(&mut discovery_req_rx, "test-version", "test-nonce").await;

        // Wait for a filter chain update from the manager.
        let filter_chain_source = wait_for_filter_chain_update(&mut filter_chain_updates_rx).await;

        let tests = vec![
            (vec![0], "filter-0"),
            (vec![1], "filter-0"),
            (vec![2], "filter-1"),
        ];

        for (version, expected) in tests {
            let packet = vec![version.clone(), String::from("hello-").into_bytes()].concat();

            // Test the new filter chain's functionality. It should append to payloads
            // based on the packet's version.
            let got = filter_chain_source.get_filter_chain(packet).unwrap();
            let response = got
                .filter_chain
                .read(ReadContext::new(
                    UpstreamEndpoints::from(
                        Endpoints::new(vec![Endpoint::new("127.0.0.1:8080".parse().unwrap())])
                            .unwrap(),
                    ),
                    "127.0.0.1:8081".parse().unwrap(),
                    got.packet,
                ))
                .unwrap();

            // Check that the version we extracted is what we expect.
            assert_eq!(&version, got.version.unwrap().as_ref());

            assert_eq!(
                format!("hello-{}", expected),
                String::from_utf8(response.contents).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn listener_manager_empty_filter_chain_type() {
        // Test that the manager creates an empty versioned or non-versioned
        // filter chain for an empty LDS filter chain depending on whether it is
        // running with versioned filter chains enabled.

        let tests = vec![
            None,
            Some(CaptureVersion {
                strategy: Strategy::Prefix,
                size: 1,
                remove: true,
            }),
        ];
        for version in tests {
            let (mut manager, mut filter_chain_updates_rx, mut discovery_req_rx) =
                create_listener_manager(version.clone());

            let (version_info, nonce) = ("1".to_string(), "1".to_string());
            manager
                .on_listener_response(create_discovery_response(
                    "1",
                    "1",
                    create_lds_proto("test", vec![]),
                ))
                .await;

            // Expect an ACK DiscoveryRequest from the manager.
            assert_discovery_request_ack(&mut discovery_req_rx, version_info, nonce).await;

            // Wait for a filter chain update from the manager.
            let filter_chain_source =
                wait_for_filter_chain_update(&mut filter_chain_updates_rx).await;

            if version.is_some() {
                // Check that a versioned filter chain was created.
                assert!(filter_chain_source
                    .get_filter_chain_non_versioned()
                    .is_none())
            } else {
                // Check that a non versioned filter chain was created.
                assert!(filter_chain_source
                    .get_filter_chain_non_versioned()
                    .is_some())
            }
        }
    }

    #[tokio::test]
    async fn listener_manager_create_empty_filter_chain() {
        // Test that the manager creates an empty filter chain update if the LDS
        //  Listener resource no filter chain.

        let (mut manager, mut filter_chain_updates_rx, mut discovery_req_rx) =
            create_listener_manager(None);

        let test_cases = vec![
            (vec![create_append_filter_proto("world")], "hello-world"),
            (vec![], "hello-"),
        ];

        for (i, (filter, expected_payload)) in test_cases.into_iter().enumerate() {
            let (version_info, nonce) = (format!("version-{}", i), format!("nonce-{}", i));
            // Send the proto message as a DiscoveryResponse to the manager.
            manager
                .on_listener_response(create_discovery_response(
                    version_info.clone(),
                    nonce.clone(),
                    create_lds_proto(
                        format!("test-listener-{}", i),
                        vec![create_lds_filter_chain(filter, None)],
                    ),
                ))
                .await;

            // Expect an ACK DiscoveryRequest from the manager.
            assert_discovery_request_ack(&mut discovery_req_rx, version_info, nonce).await;

            // Wait for a filter chain update from the manager.
            let filter_chain_source =
                wait_for_filter_chain_update(&mut filter_chain_updates_rx).await;

            // Test the new filter chain's functionality.
            let response = filter_chain_source
                .get_filter_chain_non_versioned()
                .unwrap()
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

        let test_cases = vec![
            (
                // The filter is explicitly configured to reject
                // config with this value.
                None,
                vec![create_lds_filter_chain(vec![create_append_filter_proto("reject")], None)],
                "reject requested",
            ),
            (
                // Filter does not exist in the filter registry.
                None,
                vec![create_lds_filter_chain(vec![LdsFilter {
                    name: "MissingFilter".into(),
                    config_type: Some(ConfigType::TypedConfig(prost_types::Any {
                        type_url: "MissingFilter".into(),
                        value: vec![],
                    })),
                }], None)],
                "filter `MissingFilter` not found",
            ),
            (
                // Multiple filter chains when running with non-versioned filter chains.
                None,
                (0..2)
                    .into_iter()
                    .map(|_| {
                        create_lds_filter_chain(vec![LdsFilter {
                            name: "MissingFilter".into(),
                            config_type: Some(ConfigType::TypedConfig(prost_types::Any {
                                type_url: "MissingFilter".into(),
                                value: vec![],
                            })),
                        }], None)
                    })
                    .collect(),
                "at most 1 filter chain can be provided when using a non-versioned filter chain: got 2",
            ),
            (
                // Duplicate filter chain versions
                Some(CaptureVersion{
                    strategy: Strategy::Prefix,
                    size: 1,
                    remove: true,
                }),
                (0..2)
                    .into_iter()
                    .map(|_| vec![create_append_filter_proto("hello")])
                    .map(|filter|
                        create_lds_filter_chain(filter, with_versions(vec!["AA==".into()]))
                    )
                    .collect(),
                "filter chain versions is not unique",
            ),
        ];

        for (capture_version, filter_chains, error_message) in test_cases {
            let (mut manager, _filter_chain_updates_rx, mut discovery_req_rx) =
                create_listener_manager(capture_version);

            manager
                .on_listener_response(create_discovery_response(
                    "test-version",
                    "test-nonce",
                    create_lds_proto("test", filter_chains),
                ))
                .await;

            assert_discovery_request_nack(
                &mut discovery_req_rx,
                "test-version",
                "test-nonce",
                error_message,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn listener_manager_reject_multiple_listeners() {
        // Test that the manager returns NACK DiscoveryRequests for updates with multiple listeners.

        let (mut manager, _filter_chain_updates_rx, mut discovery_req_rx) =
            create_listener_manager(None);
        let lds_listener = create_lds_listener(
            "test-listener".into(),
            vec![create_lds_filter_chain(
                vec![LdsFilter {
                    name: "MissingFilter".into(),
                    config_type: Some(ConfigType::TypedConfig(prost_types::Any {
                        type_url: "MissingFilter".into(),
                        value: vec![],
                    })),
                }],
                None,
            )],
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

        assert_discovery_request_nack(
            &mut discovery_req_rx,
            "test-version",
            "test-nonce",
            "at most 1 listener can be specified: got 2",
        )
        .await;
    }

    fn create_lds_proto(
        name: impl Into<String>,
        filter_chains: Vec<LdsFilterChain>,
    ) -> prost_types::Any {
        let lds_listener = create_lds_listener(name.into(), filter_chains);

        let mut buf = vec![];
        lds_listener.encode(&mut buf).unwrap();
        prost_types::Any {
            type_url: LISTENER_TYPE.into(),
            value: buf,
        }
    }

    fn create_append_filter_proto(value: impl Into<prost::alloc::string::String>) -> LdsFilter {
        LdsFilter {
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
        }
    }

    fn with_versions(
        versions: impl Into<prost::alloc::vec::Vec<prost::alloc::string::String>>,
    ) -> Option<FilterChainMatch> {
        Some(FilterChainMatch {
            destination_port: Default::default(),
            prefix_ranges: Default::default(),
            address_suffix: Default::default(),
            suffix_len: Default::default(),
            source_type: Default::default(),
            source_prefix_ranges: Default::default(),
            source_ports: Default::default(),
            server_names: Default::default(),
            transport_protocol: Default::default(),
            application_protocols: versions.into(),
        })
    }

    fn create_listener_manager(
        // filter_chain_updates_tx: mpsc::Sender<Arc<FilterChainSource>>,
        // discovery_req_tx: mpsc::Sender<DiscoveryRequest>,
        capture_version: Option<CaptureVersion>,
    ) -> (
        ListenerManager,
        mpsc::Receiver<Arc<FilterChainSource>>,
        mpsc::Receiver<DiscoveryRequest>,
    ) {
        let (filter_chain_updates_tx, filter_chain_updates_rx) = mpsc::channel(10);
        let (discovery_req_tx, discovery_req_rx) = mpsc::channel(10);
        let manager = ListenerManager::new(
            logger(),
            ListenerManagerArgs::new(
                Registry::default(),
                new_registry(),
                capture_version,
                filter_chain_updates_tx,
            ),
            discovery_req_tx,
        );

        (manager, filter_chain_updates_rx, discovery_req_rx)
    }

    fn create_discovery_response(
        version_info: impl Into<prost::alloc::string::String>,
        nonce: impl Into<prost::alloc::string::String>,
        resource: prost_types::Any,
    ) -> DiscoveryResponse {
        DiscoveryResponse {
            version_info: version_info.into(),
            resources: vec![resource],
            canary: false,
            type_url: LISTENER_TYPE.into(),
            nonce: nonce.into(),
            control_plane: None,
        }
    }

    async fn assert_discovery_request_ack(
        discovery_req_rx: &mut mpsc::Receiver<DiscoveryRequest>,
        version_info: impl Into<prost::alloc::string::String>,
        response_nonce: impl Into<prost::alloc::string::String>,
    ) {
        assert_discovery_request(
            discovery_req_rx,
            version_info,
            response_nonce,
            Option::<String>::None,
        )
        .await
    }
    async fn assert_discovery_request_nack(
        discovery_req_rx: &mut mpsc::Receiver<DiscoveryRequest>,
        version_info: impl Into<prost::alloc::string::String>,
        response_nonce: impl Into<prost::alloc::string::String>,
        contains_error_message: impl Into<String>,
    ) {
        assert_discovery_request(
            discovery_req_rx,
            version_info,
            response_nonce,
            Some(contains_error_message),
        )
        .await
    }
    async fn assert_discovery_request(
        discovery_req_rx: &mut mpsc::Receiver<DiscoveryRequest>,
        version_info: impl Into<prost::alloc::string::String>,
        response_nonce: impl Into<prost::alloc::string::String>,
        contains_error_message: Option<impl Into<String>>,
    ) {
        let mut discovery_req = time::timeout(Duration::from_secs(5), discovery_req_rx.recv())
            .await
            .expect("timed out waiting for DiscoveryRequest back to server")
            .unwrap();

        let error_detail = discovery_req.error_detail.take();
        assert_eq!(
            DiscoveryRequest {
                version_info: version_info.into(),
                response_nonce: response_nonce.into(),
                type_url: LISTENER_TYPE.into(),
                resource_names: vec![],
                node: None,
                error_detail: None,
            },
            discovery_req,
        );

        if let Some(error_message) = contains_error_message {
            let error_detail = error_detail.unwrap();
            let error_message = error_message.into();
            if !error_detail.message.contains(&error_message) {
                unreachable!(format!(
                    "[{}] does not contain [{}]",
                    error_detail.message, error_message
                ),)
            }
        } else {
            assert!(error_detail.is_none())
        }
    }

    async fn wait_for_filter_chain_update<T>(rx: &mut mpsc::Receiver<T>) -> T {
        time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap()
    }

    #[allow(deprecated)]
    fn create_lds_filter_chain(
        filters: Vec<LdsFilter>,
        filter_chain_match: Option<FilterChainMatch>,
    ) -> LdsFilterChain {
        LdsFilterChain {
            filter_chain_match,
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
