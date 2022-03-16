/*
 * Copyright 2021 Google LLC
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
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{watch, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::proxy::sessions::{Session, SessionKey};

// Tracks current sessions by their [`SessionKey`]
type SessionsMap = HashMap<SessionKey, Session>;
type Sessions = Arc<RwLock<SessionsMap>>;

/// SESSION_TIMEOUT_SECONDS is the default session timeout.
pub const SESSION_TIMEOUT_SECONDS: u64 = 60;

/// SESSION_EXPIRY_POLL_INTERVAL is the default interval to check for expired sessions.
const SESSION_EXPIRY_POLL_INTERVAL: u64 = 60;

#[derive(Clone)]
pub struct SessionManager(Sessions);

impl SessionManager {
    pub fn new(shutdown_rx: watch::Receiver<()>) -> Self {
        let poll_interval = Duration::from_secs(SESSION_EXPIRY_POLL_INTERVAL);
        let sessions: Sessions = Arc::new(RwLock::new(HashMap::new()));

        Self::run_prune_sessions(sessions.clone(), poll_interval, shutdown_rx);

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
        mut sessions: Sessions,
        poll_interval: Duration,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        let mut interval = tokio::time::interval(poll_interval);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Exiting Prune Sessions due to shutdown signal.");
                        break;
                    }
                    _ = interval.tick() => {
                        tracing::debug!("Attempting to Prune Sessions");
                        Self::prune_sessions(&mut sessions).await;

                    }
                }
            }
        });
    }

    /// Removes expired [`Session`]s from `sessions`. This should be run
    /// regularly such as on a time interval. This will only write lock
    /// `sessions` if it first finds expired sessions.
    async fn prune_sessions(sessions: &mut Sessions) {
        let now = if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            now.as_secs()
        } else {
            tracing::warn!("Failed to get current time when pruning sessions");
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
    use std::ops::Add;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::{mpsc, watch, RwLock};

    use crate::{
        endpoint::{Endpoint, EndpointAddress},
        filters::SharedFilterChain,
        proxy::{
            server::metrics::Metrics as ProxyMetrics,
            sessions::{
                metrics::Metrics, session::SessionArgs, session_manager::Sessions, SessionKey,
                UpstreamPacket,
            },
        },
    };

    use super::SessionManager;

    fn address_pair() -> (EndpointAddress, EndpointAddress) {
        (
            (std::net::Ipv4Addr::LOCALHOST, 7000).into(),
            (std::net::Ipv4Addr::LOCALHOST, 7001).into(),
        )
    }

    #[tokio::test]
    async fn run_prune_sessions() {
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let (from, to) = address_pair();
        let (send, _recv) = mpsc::channel::<UpstreamPacket>(1);
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        let endpoint = Endpoint::new(to.clone());

        let ttl = Duration::from_secs(1);
        let poll_interval = Duration::from_millis(1);

        //let config = Arc::new(config_with_dummy_endpoint().build());
        //let server = Builder::from(config).validate().unwrap().build();
        SessionManager::run_prune_sessions(sessions.clone(), poll_interval, shutdown_rx);

        let key = SessionKey::from((from.clone(), to.clone()));

        // Insert key.
        {
            let mut sessions = sessions.write().await;
            let session_args = SessionArgs {
                metrics: Metrics::new().unwrap(),
                proxy_metrics: ProxyMetrics::new().unwrap(),
                filter_chain: SharedFilterChain::empty(),
                source: from,
                dest: endpoint.clone(),
                sender: send,
                ttl,
            };
            sessions.insert(key.clone(), session_args.into_session().await.unwrap());
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
        let mut sessions: Sessions = Arc::new(RwLock::new(HashMap::new()));
        let (from, to) = address_pair();
        let (send, _recv) = mpsc::channel::<UpstreamPacket>(1);
        let endpoint = Endpoint::new(to.clone());

        let key = SessionKey::from((from.clone(), to.clone()));
        let ttl = Duration::from_secs(1);

        {
            let mut sessions = sessions.write().await;
            let session_args = SessionArgs {
                metrics: Metrics::new().unwrap(),
                proxy_metrics: ProxyMetrics::new().unwrap(),
                filter_chain: SharedFilterChain::empty(),
                source: from,
                dest: endpoint.clone(),
                sender: send,
                ttl,
            };
            sessions.insert(key.clone(), session_args.into_session().await.unwrap());
        }

        // Insert key.
        {
            let map = sessions.read().await;
            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // session map should be the same since, we haven't passed expiry
        SessionManager::prune_sessions(&mut sessions).await;
        {
            let map = sessions.read().await;
            assert!(map.contains_key(&key));
            assert_eq!(1, map.len());
        }

        // Wait until the key has expired.
        tokio::time::sleep_until(tokio::time::Instant::now().add(ttl)).await;

        SessionManager::prune_sessions(&mut sessions).await;
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
