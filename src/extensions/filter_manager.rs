/*
 * Copyright 2021 Google LLC All Rights Reserved.
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

// TODO: Allow unused variables since this module is WIP.
#![allow(unused)]

use crate::extensions::{FilterChain, FilterRegistry};

use std::sync::Arc;

use parking_lot::RwLock;
use slog::{debug, o, warn, Logger};
use tokio::sync::mpsc;
use tokio::sync::watch;

/// The max size of queue that provides updates from the XDS layer to the [`ClusterManager`].
const FILTER_CHAIN_UPDATE_QUEUE_SIZE: usize = 1000;

pub type SharedFilterManager = Arc<RwLock<FilterManager>>;

/// FilterManager creates and updates the filter chain.
pub struct FilterManager {
    log: Logger,
    /// The current filter chain.
    filter_chain: Option<Arc<FilterChain>>,
}

/// ListenerManagerArgs contains arguments when invoking the LDS resource manager.
pub(crate) struct ListenerManagerArgs {
    pub filter_registry: Arc<FilterRegistry>,
    pub filter_chain_updates_tx: mpsc::Sender<Arc<FilterChain>>,
}

impl ListenerManagerArgs {
    pub fn new(
        filter_registry: Arc<FilterRegistry>,
        filter_chain_updates_tx: mpsc::Sender<Arc<FilterChain>>,
    ) -> ListenerManagerArgs {
        ListenerManagerArgs {
            filter_registry,
            filter_chain_updates_tx,
        }
    }
}

impl FilterManager {
    fn update(&mut self, filter_chain: Arc<FilterChain>) {
        self.filter_chain = Some(filter_chain);
    }

    /// Returns the current filter chain.
    pub fn get_filter_chain(&self) -> &Option<Arc<FilterChain>> {
        &self.filter_chain
    }

    /// Returns a new instance backed only by the provided filter chain.
    pub fn fixed(base_logger: Logger, filter_chain: Arc<FilterChain>) -> SharedFilterManager {
        Arc::new(RwLock::new(FilterManager {
            filter_chain: Some(filter_chain),
            log: Self::create_logger(base_logger),
        }))
    }

    /// Returns a new instance backed by a stream of filter chain updates.
    /// Updates from the provided stream will be reflected in the current filter chain.
    pub fn dynamic(
        base_logger: Logger,
        filter_chain_update: Arc<FilterChain>,
        filter_chain_updates_rx: mpsc::Receiver<Arc<FilterChain>>,
        shutdown_rx: watch::Receiver<()>,
    ) -> SharedFilterManager {
        let log = Self::create_logger(base_logger);

        let filter_manager = Arc::new(RwLock::new(FilterManager {
            filter_chain: None,
            log: log.clone(),
        }));

        // Start a task in the background to receive LDS updates
        // and update the FilterManager's filter chain in turn.
        Self::spawn_updater(
            log,
            filter_manager.clone(),
            filter_chain_updates_rx,
            shutdown_rx,
        );

        filter_manager
    }

    /// Spawns a task in the background that listens for filter chain updates and
    /// updates the filter manager's current filter in turn.
    fn spawn_updater(
        log: Logger,
        filter_manager: SharedFilterManager,
        mut filter_chain_updates_rx: mpsc::Receiver<Arc<FilterChain>>,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    update = filter_chain_updates_rx.recv() => {
                        match update {
                            Some(filter_chain) => {
                                debug!(log, "Received a filter chain update.");
                                filter_manager.write().update(filter_chain);
                            }
                            None => {
                                warn!(log, "Exiting filter chain update receive loop because the sender dropped the channel.");
                                return;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        debug!(log, "Exiting filter chain update receive loop because a shutdown signal was received.");
                        return;
                    },
                }
            }
        });
    }

    fn create_logger(base_logger: Logger) -> Logger {
        base_logger.new(o!("source" => "FilterManager"))
    }
}

#[cfg(test)]
mod tests {
    use super::FilterManager;
    use crate::extensions::{DownstreamContext, DownstreamResponse, Filter, FilterChain};
    use crate::test_utils::logger;

    use std::sync::Arc;

    use crate::cluster::Endpoint;
    use crate::config::{Endpoints, UpstreamEndpoints};
    use tokio::sync::mpsc;
    use tokio::sync::watch;

    #[ignore]
    #[tokio::test]
    async fn spawn_updater() {
        let filter_manager = FilterManager::fixed(logger(), Arc::new(FilterChain::new(vec![])));
        let (filter_chain_updates_tx, filter_chain_updates_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        FilterManager::spawn_updater(
            logger(),
            filter_manager.clone(),
            filter_chain_updates_rx,
            shutdown_rx,
        );

        let manager_guard = filter_manager.read();
        let filter_chain = manager_guard.get_filter_chain().as_ref().unwrap();

        let test_endpoints = Endpoints::new(vec![Endpoint::from_address(
            "127.0.0.1:8080".parse().unwrap(),
        )])
        .unwrap();
        let response = filter_chain.on_downstream_receive(DownstreamContext::new(
            UpstreamEndpoints::from(test_endpoints.clone()),
            "127.0.0.1:8081".parse().unwrap(),
            vec![],
        ));
        assert!(response.is_some());

        struct Drop;
        impl Filter for Drop {
            fn on_downstream_receive(&self, _: DownstreamContext) -> Option<DownstreamResponse> {
                None
            }
        }

        let filter_chain = Arc::new(FilterChain::new(vec![Box::new(Drop)]));
        assert!(filter_chain_updates_tx.send(filter_chain).await.is_ok());

        let mut num_iterations = 0;
        loop {
            // Wait for the new filter chain to be applied.
            // The new filter chain drops packets instead.
            let manager_guard = filter_manager.read();
            let filter_chain = manager_guard.get_filter_chain().as_ref().unwrap();
            if filter_chain
                .on_downstream_receive(DownstreamContext::new(
                    UpstreamEndpoints::from(test_endpoints.clone()),
                    "127.0.0.1:8081".parse().unwrap(),
                    vec![],
                ))
                .is_none()
            {
                break;
            }

            num_iterations += 1;
            if num_iterations > 1000 {
                unreachable!("timed-out waiting for new filter chain to be applied");
            }

            println!("sleep start");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            println!("sleep end");
        }
    }
}
