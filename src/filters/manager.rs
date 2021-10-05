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

use crate::filters::{chain::Error as FilterChainError, FilterRegistry};

use std::sync::Arc;

use crate::config::CaptureVersion;
use crate::filters::chain::FilterChainSource;
use parking_lot::RwLock;
use prometheus::Registry;
use slog::{debug, o, warn, Logger};
use tokio::sync::mpsc;
use tokio::sync::watch;

pub(crate) type SharedFilterManager = Arc<RwLock<FilterManager>>;

/// FilterManager creates and updates the filter chain.
pub(crate) struct FilterManager {
    /// The current filter chain implementation.
    filter_chain_source: Arc<FilterChainSource>,
}

/// ListenerManagerArgs contains arguments when invoking the LDS resource manager.
pub(crate) struct ListenerManagerArgs {
    /// The configuration for how to capture version from packets.
    /// This is used to validate versioned filters received from
    /// the management server as well as when re-creating new filter
    /// chain instances afterwards.
    pub capture_version: Option<CaptureVersion>,
    pub filter_chain_updates_tx: mpsc::Sender<Arc<FilterChainSource>>,
    pub filter_registry: FilterRegistry,
    pub metrics_registry: Registry,
}

impl ListenerManagerArgs {
    pub fn new(
        metrics_registry: Registry,
        filter_registry: FilterRegistry,
        capture_version: Option<CaptureVersion>,
        filter_chain_updates_tx: mpsc::Sender<Arc<FilterChainSource>>,
    ) -> ListenerManagerArgs {
        ListenerManagerArgs {
            capture_version,
            filter_chain_updates_tx,
            filter_registry,
            metrics_registry,
        }
    }
}

impl FilterManager {
    fn update(&mut self, filter_chain_source: Arc<FilterChainSource>) {
        self.filter_chain_source = filter_chain_source;
    }

    /// Returns the current filter chain implementation.
    pub fn get_filter_chain_source(&self) -> &FilterChainSource {
        self.filter_chain_source.as_ref()
    }

    /// Returns a new instance backed only by the provided filter chain implementation.
    pub fn fixed(filter_chain_source: Arc<FilterChainSource>) -> SharedFilterManager {
        Arc::new(RwLock::new(FilterManager {
            filter_chain_source,
        }))
    }

    /// Returns a new instance backed by a stream of filter chain updates.
    /// Updates from the provided stream will be reflected in the current filter chain.
    pub fn dynamic(
        base_logger: Logger,
        filter_chain_source: Arc<FilterChainSource>,
        filter_chain_updates_rx: mpsc::Receiver<Arc<FilterChainSource>>,
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<SharedFilterManager, FilterChainError> {
        let log = Self::create_logger(base_logger);

        let filter_manager = Arc::new(RwLock::new(FilterManager {
            filter_chain_source,
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
        mut filter_chain_updates_rx: mpsc::Receiver<Arc<FilterChainSource>>,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    update = filter_chain_updates_rx.recv() => {
                        match update {
                            Some(filter_chain_source) => {
                                debug!(log, "Received a filter chain update.");
                                filter_manager.write().update(filter_chain_source);
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
    use crate::filters::{
        Filter, FilterChain, FilterChainSource, FilterInstance, ReadContext, ReadResponse,
    };
    use crate::test_utils::logger;

    use std::time::Duration;

    use crate::endpoint::{Endpoint, Endpoints, UpstreamEndpoints};
    use tokio::sync::mpsc;
    use tokio::sync::watch;
    use tokio::time::sleep;

    #[tokio::test]
    async fn dynamic_filter_manager_update_filter_chain() {
        let registry = prometheus::Registry::default();
        let filter_manager = FilterManager::fixed(FilterChainSource::non_versioned(
            FilterChain::new(vec![], &registry).unwrap(),
        ));
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
            manager_guard
                .get_filter_chain_source()
                .get_filter_chain(vec![])
                .unwrap()
                .filter_chain
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
        let filter_chain = FilterChain::new(
            vec![(
                "Drop".into(),
                FilterInstance::new(serde_json::Value::Null, Box::new(Drop) as Box<dyn Filter>),
            )],
            &registry,
        )
        .unwrap();
        assert!(filter_chain_updates_tx
            .send(FilterChainSource::non_versioned(filter_chain))
            .await
            .is_ok());

        let mut num_iterations = 0;
        loop {
            // Wait for the new filter chain to be applied.
            // The new filter chain drops packets instead.
            let filter_chain = {
                let manager_guard = filter_manager.read();
                manager_guard
                    .get_filter_chain_source()
                    .get_filter_chain(vec![])
                    .unwrap()
                    .filter_chain
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
        let filter_manager = FilterManager::fixed(FilterChainSource::non_versioned(
            FilterChain::new(vec![], &registry).unwrap(),
        ));
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
        assert!(filter_chain_updates_tx
            .send(FilterChainSource::non_versioned(
                FilterChain::new(vec![], &registry).unwrap()
            ))
            .await
            .is_err());
    }
}
