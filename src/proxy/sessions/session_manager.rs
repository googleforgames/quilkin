use crate::proxy::sessions::Session;
use slog::{debug, error, warn, Logger};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

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
    pub fn new(log: Logger) -> Self {
        let poll_interval = Duration::from_secs(SESSION_EXPIRY_POLL_INTERVAL);
        let sessions: Sessions = Arc::new(RwLock::new(HashMap::new()));

        Self::run_prune_sessions(log.clone(), sessions.clone(), poll_interval);

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
    fn run_prune_sessions(log: Logger, mut sessions: Sessions, poll_interval: Duration) {
        tokio::spawn(async move {
            // TODO: Add a shutdown channel to this task.
            loop {
                tokio::time::sleep(poll_interval).await;
                debug!(log, "Attempting to Prune Sessions");
                Self::prune_sessions(&log, &mut sessions).await;
            }
        });
    }

    /// prune_sessions removes expired Sessions from the Sessions map.
    /// Should be run on a time interval.
    /// This will lock the Sessions map if it finds expired sessions
    async fn prune_sessions(log: &Logger, sessions: &mut Sessions) {
        let now = if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            now.as_secs()
        } else {
            warn!(log, "Failed to get current time when pruning sessions");
            return;
        };

        let mut expired_keys = Vec::<(SocketAddr, SocketAddr)>::new();
        {
            let map = sessions.read().await;
            for (key, session) in map.iter() {
                let expiration = session.expiration();
                if expiration <= now {
                    expired_keys.push(*key);
                }
            }
        }

        if !expired_keys.is_empty() {
            let mut map = sessions.write().await;
            for key in expired_keys.iter() {
                if let Some(session) = map.get(key) {
                    // If the session has been updated since we marked it
                    // for removal then its still valid so ignore it.
                    if session.expiration() > now {
                        continue;
                    }

                    if let Err(err) = session.close() {
                        error!(log, "Error closing Session"; "error" => %err)
                    }
                }
                map.remove(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionManager;
    use crate::cluster::Endpoint;
    use crate::extensions::filter_manager::FilterManager;
    use crate::extensions::FilterChain;
    use crate::proxy::sessions::session_manager::Sessions;
    use crate::proxy::sessions::{Packet, Session};
    use crate::proxy::Metrics;
    use crate::test_utils::TestHelper;
    use prometheus::Registry;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::ops::Add;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{mpsc, RwLock};

    #[tokio::test]
    async fn run_prune_sessions() {
        let t = TestHelper::default();
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        let from: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let to: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let (send, _recv) = mpsc::channel::<Packet>(1);

        let endpoint = Endpoint::from_address(to);

        let ttl = Duration::from_secs(1);
        let poll_interval = Duration::from_millis(1);

        //let config = Arc::new(config_with_dummy_endpoint().build());
        //let server = Builder::from(config).validate().unwrap().build();
        SessionManager::run_prune_sessions(t.log.clone(), sessions.clone(), poll_interval);

        let key = (from, to);

        // Insert key.
        {
            let mut sessions = sessions.write().await;
            sessions.insert(
                key,
                Session::new(
                    &t.log,
                    Metrics::new(&t.log, Registry::default())
                        .new_session_metrics(&from, &endpoint.address)
                        .unwrap(),
                    FilterManager::fixed(Arc::new(FilterChain::new(vec![]))),
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
            let mut sessions = sessions.write().await;
            sessions.insert(
                key,
                Session::new(
                    &t.log,
                    Metrics::new(&t.log, Registry::default())
                        .new_session_metrics(&from, &endpoint.address)
                        .unwrap(),
                    FilterManager::fixed(Arc::new(FilterChain::new(vec![]))),
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
