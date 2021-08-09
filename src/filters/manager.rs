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

use crate::filters::{chain::Error as FilterChainError, FilterChain, FilterRegistry};

use std::sync::Arc;

use parking_lot::RwLock;
use prometheus::Registry;
use slog::{debug, o, warn, Logger};
use tokio::sync::mpsc;
use tokio::sync::watch;

pub type SharedFilterManager = Arc<RwLock<FilterManager>>;

/// FilterManager creates and updates the filter chain.
pub struct FilterManager {
    /// The current filter chain.
    filter_chain: Arc<FilterChain>,
}

/// ListenerManagerArgs contains arguments when invoking the LDS resource manager.
pub(crate) struct ListenerManagerArgs {
    pub filter_chain_updates_tx: mpsc::Sender<Arc<FilterChain>>,
    pub filter_registry: FilterRegistry,
    pub metrics_registry: Registry,
}

impl ListenerManagerArgs {
    pub fn new(
        metrics_registry: Registry,
        filter_registry: FilterRegistry,
        filter_chain_updates_tx: mpsc::Sender<Arc<FilterChain>>,
    ) -> ListenerManagerArgs {
        ListenerManagerArgs {
            filter_chain_updates_tx,
            filter_registry,
            metrics_registry,
        }
    }
}

impl FilterManager {
    fn update(&mut self, filter_chain: Arc<FilterChain>) {
        self.filter_chain = filter_chain;
    }

    /// Returns the current filter chain.
    pub fn get_filter_chain(&self) -> Arc<FilterChain> {
        self.filter_chain.clone()
    }

    /// Returns a new instance backed only by the provided filter chain.
    pub fn fixed(filter_chain: Arc<FilterChain>) -> SharedFilterManager {
        Arc::new(RwLock::new(FilterManager { filter_chain }))
    }

    /// Returns a new instance backed by a stream of filter chain updates.
    /// Updates from the provided stream will be reflected in the current filter chain.
    pub fn dynamic(
        base_logger: Logger,
        metrics_registry: &Registry,
        filter_chain_updates_rx: mpsc::Receiver<Arc<FilterChain>>,
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<SharedFilterManager, FilterChainError> {
        let log = Self::create_logger(base_logger);

        let filter_manager = Arc::new(RwLock::new(FilterManager {
            // Start out with an empty filter chain.
            filter_chain: Arc::new(FilterChain::new(vec![], metrics_registry)?),
        }));

        // Start a task in the background to receive LDS updates
        // and update the FilterManager's filter chain in turn.
        Self::spawn_updater(
            log,
            filter_manager.clone(),
            filter_chain_updates_rx,
            shutdown_rx,
        );

        Ok(filter_manager)
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
    use crate::filters::{Filter, FilterChain, ReadContext, ReadResponse};
    use crate::test_utils::logger;

    use std::sync::Arc;
    use std::time::Duration;

    use crate::endpoint::{Endpoint, Endpoints, UpstreamEndpoints};
    use tokio::sync::mpsc;
    use tokio::sync::watch;
    use tokio::time::sleep;

    #[tokio::test]
    async fn dynamic_filter_manager_update_filter_chain() {
        let registry = prometheus::Registry::default();
        let filter_manager =
            FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap()));
        let (filter_chain_updates_tx, filter_chain_updates_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        FilterManager::spawn_updater(
            logger(),
            filter_manager.clone(),
            filter_chain_updates_rx,
            shutdown_rx,
        );

        let filter_chain = {
            let manager_guard = filter_manager.read();
            manager_guard.get_filter_chain().clone()
        };

        let test_endpoints =
            Endpoints::new(vec![Endpoint::new("127.0.0.1:8080".parse().unwrap())]).unwrap();
        let response = filter_chain.read(ReadContext::new(
            UpstreamEndpoints::from(test_endpoints.clone()),
            "127.0.0.1:8081".parse().unwrap(),
            vec![],
        ));
        assert!(response.is_some());

        // A simple test filter that drops all packets flowing upstream.
        struct Drop;
        impl Filter for Drop {
            fn read(&self, _: ReadContext) -> Option<ReadResponse> {
                None
            }
        }
        let filter_chain =
            Arc::new(FilterChain::new(vec![("Drop".into(), Box::new(Drop))], &registry).unwrap());
        assert!(filter_chain_updates_tx.send(filter_chain).await.is_ok());

        let mut num_iterations = 0;
        loop {
            // Wait for the new filter chain to be applied.
            // The new filter chain drops packets instead.
            let filter_chain = {
                let manager_guard = filter_manager.read();
                manager_guard.get_filter_chain().clone()
            };
            if filter_chain
                .read(ReadContext::new(
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

            sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn dynamic_filter_manager_shutdown_task_on_shutdown_signal() {
        // Test that we shut down the background task if we receive a shutdown signal.

        let registry = prometheus::Registry::default();
        let filter_manager =
            FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap()));
        let (filter_chain_updates_tx, filter_chain_updates_rx) = mpsc::channel(10);
        let (shutdown_tx, shutdown_rx) = watch::channel(());

        FilterManager::spawn_updater(
            logger(),
            filter_manager.clone(),
            filter_chain_updates_rx,
            shutdown_rx,
        );

        // Send a shutdown signal.
        shutdown_tx.send(()).unwrap();

        // Wait a bit for the signal to be processed.
        sleep(Duration::from_millis(10)).await;

        // Send a filter chain update on the channel. This should fail
        // since the listening task should have shut down.
        let filter_chain = Arc::new(FilterChain::new(vec![], &registry).unwrap());
        assert!(filter_chain_updates_tx.send(filter_chain).await.is_err());
    }
}
