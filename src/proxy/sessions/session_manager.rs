/*
 * Copyright 2021 Google LLC All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use slog::{debug, warn, Logger};
use tokio::sync::{watch, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::proxy::sessions::Session;

// Tracks current sessions keyed by key (source_address,destination_address) pair.
type SessionsMap = HashMap<(SocketAddr, SocketAddr), Session>;
type Sessions = Arc<RwLock<SessionsMap>>;

/// SESSION_TIMEOUT_SECONDS is the default session timeout.
pub const SESSION_TIMEOUT_SECONDS: u64 = 60;

/// SESSION_EXPIRY_POLL_INTERVAL is the default interval to check for expired sessions.
const SESSION_EXPIRY_POLL_INTERVAL: u64 = 60;

#[derive(Clone)]
pub struct SessionManager(Sessions);

impl SessionManager {
    pub fn new(log: Logger, shutdown_rx: watch::Receiver<()>) -> Self {
        let poll_interval = Duration::from_secs(SESSION_EXPIRY_POLL_INTERVAL);
        let sessions: Sessions = Arc::new(RwLock::new(HashMap::new()));

        Self::run_prune_sessions(log.clone(), sessions.clone(), poll_interval, shutdown_rx);

        Self(sessions)
    }

    pub async fn get_sessions(&self) -> RwLockReadGuard<'_, SessionsMap> {
        self.0.read().await
    }

    pub async fn get_sessions_mut(&self) -> RwLockWriteGuard<'_, SessionsMap> {
        self.0.write().await
    }

    /// run_prune_sessions starts the timer for pruning sessions and runs prune_sessions every
    /// SESSION_TIMEOUT_SECONDS, via a tokio::spawn, i.e. it's non-blocking.
    /// Pruning will occur ~ every interval period. So the timeout expiration may sometimes
    /// exceed the expected, but we don't have to write lock the Sessions map as often to clean up.
    fn run_prune_sessions(
        log: Logger,
        mut sessions: Sessions,
        poll_interval: Duration,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        let mut interval = tokio::time::interval(poll_interval);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        debug!(log, "Exiting Prune Sessions due to shutdown signal.");
                        break;
                    }
                    _ = interval.tick() => {
                        debug!(log, "Attempting to Prune Sessions");
                        Self::prune_sessions(&log, &mut sessions).await;

                    }
                }
            }
        });
    }

    /// Removes expired [`Session`]s from `sessions`. This should be run
    /// regularly such as on a time interval. This will only write lock
    /// `sessions` if it first finds expired sessions.
    async fn prune_sessions(log: &Logger, sessions: &mut Sessions) {
        let now = if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            now.as_secs()
        } else {
            warn!(log, "Failed to get current time when pruning sessions");
            return;
        };

        let expired_keys = (*sessions.read().await)
            .iter()
            .filter(|(_, session)| session.expiration() <= now)
            .count();

        if expired_keys != 0 {
            // Go over the whole sessions map again in case anything expired
            // since acquiring the write lock.
            sessions
                .write()
                .await
                .retain(|_, session| session.expiration() > now);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::ops::Add;
    use std::sync::Arc;
    use std::time::Duration;

    use prometheus::Registry;
    use tokio::sync::{mpsc, watch, RwLock};

    use crate::cluster::Endpoint;
    use crate::extensions::filter_manager::FilterManager;
    use crate::extensions::FilterChain;
    use crate::proxy::sessions::metrics::Metrics;
    use crate::proxy::sessions::session_manager::Sessions;
    use crate::proxy::sessions::{Packet, Session};
    use crate::test_utils::TestHelper;

    use super::SessionManager;

    #[tokio::test]
    async fn run_prune_sessions() {
        let t = TestHelper::default();
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let to: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (send, _recv) = mpsc::channel::<Packet>(1);
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        let endpoint = Endpoint::from_address(to);

        let ttl = Duration::from_secs(1);
        let poll_interval = Duration::from_millis(1);

        //let config = Arc::new(config_with_dummy_endpoint().build());
        //let server = Builder::from(config).validate().unwrap().build();
        SessionManager::run_prune_sessions(
            t.log.clone(),
            sessions.clone(),
            poll_interval,
            shutdown_rx,
        );

        let key = (from, to);

        // Insert key.
        {
            let registry = Registry::default();
            let mut sessions = sessions.write().await;
            sessions.insert(
                key,
                Session::new(
                    &t.log,
                    Metrics::new(&registry).unwrap(),
                    FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
                    from,
                    endpoint.clone(),
                    send,
                    ttl,
                )
                .await
                .unwrap(),
            );
        }

        // session map should be the same since, we haven't passed expiry
        {
            let map = sessions.read().await;

            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // Wait until the key has expired.
        tokio::time::sleep_until(tokio::time::Instant::now().add(ttl)).await;

        // poll, since cleanup is async, and may not have happened yet
        for _ in 1..10000 {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let map = sessions.read().await;
            if !map.contains_key(&key) && map.len() == 0 {
                break;
            }
        }
        // do final assertion
        {
            let map = sessions.read().await;
            assert!(
                !map.contains_key(&key),
                "should not contain the key after prune"
            );
            assert_eq!(0, map.len(), "len should be 0, bit is {}", map.len());
        }
    }

    #[tokio::test]
    async fn prune_sessions() {
        let t = TestHelper::default();
        let mut sessions: Sessions = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let to: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (send, _recv) = mpsc::channel::<Packet>(1);
        let endpoint = Endpoint::from_address(to);

        let key = (from, to);
        let ttl = Duration::from_secs(1);

        {
            let registry = Registry::default();
            let mut sessions = sessions.write().await;
            sessions.insert(
                key,
                Session::new(
                    &t.log,
                    Metrics::new(&registry).unwrap(),
                    FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
                    from,
                    endpoint.clone(),
                    send,
                    ttl,
                )
                .await
                .unwrap(),
            );
        }

        // Insert key.
        {
            let map = sessions.read().await;
            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // session map should be the same since, we haven't passed expiry
        SessionManager::prune_sessions(&t.log, &mut sessions).await;
        {
            let map = sessions.read().await;
            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // Wait until the key has expired.
        tokio::time::sleep_until(tokio::time::Instant::now().add(ttl)).await;

        SessionManager::prune_sessions(&t.log, &mut sessions).await;
        {
            let map = sessions.read().await;
            assert!(
                !map.contains_key(&key),
                "should not contain the key after prune"
            );
            assert_eq!(0, map.len(), "len should be 0, bit is {}", map.len());
        }
    }
}
