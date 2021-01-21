/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use crate::extensions::filter_manager::ListenerManagerArgs;
use crate::extensions::{FilterChain as ProxyFilterChain, FilterRegistry};
use crate::xds::envoy::config::listener::v3::{filter::ConfigType, FilterChain, Listener};
use crate::xds::envoy::service::discovery::v3::{DiscoveryRequest, DiscoveryResponse};
use crate::xds::error::Error;
use crate::xds::LISTENER_TYPE;

use std::sync::Arc;

use crate::xds::ads_client::send_discovery_req;
use bytes::Bytes;
use prost::Message;
use slog::{debug, warn, Logger};
use tokio::sync::mpsc;

/// Tracks FilterChain resources on the LDS DiscoveryResponses and
/// instantiates a corresponding proxy filter chain and exposes it
/// to the caller whenever the filter chain changes.
pub(crate) struct ListenerManager {
    log: Logger,

    // Registry to lookup filter factories by name.
    filter_registry: Arc<FilterRegistry>,

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

        println!("processed listener reponse: is ok? = {:?}", result.is_ok());
        let error_message = match result {
            Ok(filter_chain) => {
                self.filter_chain_updates_tx
                    .send(Arc::new(filter_chain))
                    .await
                    .map_err(|err| {
                        warn!(self.log, "failed to send filter chain update on channel");
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
            0 => return Ok(ProxyFilterChain::new(vec![])),
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
            0 => return Ok(ProxyFilterChain::new(vec![])),
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
            let config = match filter.config_type {
                Some(ConfigType::TypedConfig(config)) => Some(config),
                None => None,
            };

            let filter = self
                .filter_registry
                .get_from_xds_config(&filter.name, config)
                .map_err(|err| Error::new(format!("{}", err)))?;

            filters.push(filter);
        }

        Ok(ProxyFilterChain::new(filters))
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

    // Notify that we are about to reconnect the GRPC stream.
    pub(in crate::xds) fn on_reconnect(&mut self) {
        // Nothing to do.
    }
}
