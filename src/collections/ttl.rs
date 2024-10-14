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

use tracing::warn;

use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot::{channel, Receiver, Sender};

type HashMap<K, V, S = gxhash::GxBuildHasher> = papaya::HashMap<K, V, S>;

// Clippy isn't recognizing that these imports are used conditionally.
#[allow(unused_imports)]
use std::time::{SystemTime, UNIX_EPOCH};
#[allow(unused_imports)]
use tokio::time::Instant;

/// A wrapper around the value of an entry in the map.
/// It contains the value's ttl.
pub struct Value<V> {
    pub value: V,
    expires_at: Arc<AtomicU64>,
    clock: Clock,
}

impl<V> Value<V> {
    fn new(value: V, ttl: Duration, clock: Clock) -> Value<V> {
        let value = Value {
            value,
            expires_at: Arc::new(AtomicU64::new(0)),
            clock,
        };
        value.update_expiration(ttl);
        value
    }

    /// Get the expiration time for this value. The returned value is the
    /// number of seconds relative to some reference point (e.g UNIX_EPOCH), based
    /// on the clock being used.
    fn expiration_secs(&self) -> u64 {
        self.expires_at.load(Ordering::Relaxed)
    }

    /// Update the value's expiration time to (now + TTL).
    fn update_expiration(&self, ttl: Duration) {
        match self.clock.compute_expiration_secs(ttl) {
            Ok(new_expiration_time) => {
                self.expires_at
                    .store(new_expiration_time, Ordering::Relaxed);
            }
            Err(err) => {
                warn!("failed to increment key expiration: {}", err);
            }
        }
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for Value<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Value")
            .field("value", &self.value)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl<V> std::ops::Deref for Value<V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Map contains the hash map implementation.
struct Map<K, V> {
    inner: HashMap<K, Value<V>, gxhash::GxBuildHasher>,
    ttl: Duration,
    clock: Clock,
    shutdown_tx: Option<Sender<()>>,
}

impl<K: std::fmt::Debug + std::hash::Hash + std::cmp::Eq, V: std::fmt::Debug> std::fmt::Debug
    for Map<K, V>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Map")
            .field("inner", &self.inner)
            .field("ttl", &self.ttl)
            .field("shutdown_tx", &self.shutdown_tx)
            .finish()
    }
}

impl<K, V> Drop for Map<K, V> {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            shutdown_tx.send(()).ok();
        }
    }
}

/// TtlMap is a key value hash map where entries are associated with a TTL.
/// When the TTL for an entry elapses, the entry is removed from the map.
/// The TTL is reset each time the entry is (re)inserted or read via [`TtlMap::get`],
/// [`TtlMap::get_mut`] functions, or via the [`TtlMap::entry`] interface.
/// During tests, the internal clock implementation is driven by [`tokio::time`] so
/// functions like [`tokio::time::pause`] and [`tokio::time::advance`] can be used.
pub struct TtlMap<K, V>(Arc<Map<K, V>>);

impl<K, V> TtlMap<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    pub fn new(ttl: Duration, poll_interval: Duration) -> Self {
        Self::initialize(<_>::default(), ttl, poll_interval)
    }

    #[allow(dead_code)]
    pub fn with_capacity(ttl: Duration, poll_interval: Duration, capacity: usize) -> Self {
        Self::initialize(
            HashMap::with_capacity_and_hasher(capacity, <_>::default()),
            ttl,
            poll_interval,
        )
    }

    fn initialize(inner: HashMap<K, Value<V>>, ttl: Duration, poll_interval: Duration) -> Self {
        let (shutdown_tx, shutdown_rx) = channel();
        let map = TtlMap(Arc::new(Map {
            inner,
            shutdown_tx: Some(shutdown_tx),
            ttl,
            clock: Clock::new(),
        }));
        spawn_cleanup_task(
            map.0.clone(),
            poll_interval,
            map.0.clock.clone(),
            shutdown_rx,
        );
        map
    }

    /// Returns the current time as the number of seconds relative to some initial
    /// reference point (e.g UNIX_EPOCH), based on the clock implementation being used.
    /// In tests, this will be driven by [`tokio::time`]
    pub(crate) fn now_relative_secs(&self) -> u64 {
        self.0.clock.now_relative_secs().unwrap_or_default()
    }
}

impl<K, V> TtlMap<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Send + Sync + Clone,
{
    /// Returns a reference to value corresponding to key.
    pub fn get(&self, key: &K) -> Option<V> {
        let pin = self.0.inner.pin();
        let value = pin.get(key);
        if let Some(value) = value {
            value.update_expiration(self.0.ttl);
        }

        value.map(|value| value.value.clone())
    }
}

impl<K, V> TtlMap<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Send + Sync,
{
    /// Returns a reference to value corresponding to key.
    pub fn get_by_ref<F>(&self, key: &K, and_then: impl FnOnce(&V) -> F) -> Option<F> {
        let pin = self.0.inner.pin();
        let value = pin.get(key);
        if let Some(value) = value {
            value.update_expiration(self.0.ttl);
            Some((and_then)(value))
        } else {
            None
        }
    }

    /// Returns the number of entries currently in the map.
    pub fn len(&self) -> usize {
        self.0.inner.len()
    }

    /// Returns whether the map currently contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether the map currently contains any entries.
    pub fn is_not_empty(&self) -> bool {
        !self.is_empty()
    }

    /// Returns true if the map contains a value for the specified key.
    pub fn contains_key(&self, key: &K) -> bool {
        self.0.inner.pin().contains_key(key)
    }

    /// Inserts a key-value pair into the map.
    /// The value will be set to expire at the configured TTL after the time of insertion.
    /// If a previous value existed for this key, that value is returned.
    pub fn insert(&self, key: K, value: V) {
        self.0
            .inner
            .pin()
            .insert(key, Value::new(value, self.0.ttl, self.0.clock.clone()));
    }

    /// Removes a key-value pair from the map.
    pub fn remove(&self, key: K) -> bool {
        self.0.inner.pin().remove(&key).is_some()
    }

    /// Removes a key-value pair from the map.
    #[cfg(test)]
    pub fn remove_force_drop(&self, key: K) -> bool {
        use papaya::Guard;
        let guard = self.0.inner.guard();
        let removed = self.0.inner.remove(&key, &guard).is_some();
        guard.flush();
        removed
    }
}

impl<K: std::fmt::Debug + std::hash::Hash + std::cmp::Eq, V: std::fmt::Debug> std::fmt::Debug
    for TtlMap<K, V>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtlMap").field("inner", &self.0).finish()
    }
}

impl<K, V> Clone for TtlMap<K, V> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<K, V> Default for TtlMap<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    fn default() -> Self {
        const DEFAULT_TIMEOUT_SECONDS: Duration = Duration::from_secs(60);
        const DEFAULT_EXPIRY_POLL_INTERVAL: Duration = Duration::from_secs(60);
        Self::new(DEFAULT_TIMEOUT_SECONDS, DEFAULT_EXPIRY_POLL_INTERVAL)
    }
}

fn spawn_cleanup_task<K, V>(
    map: Arc<Map<K, V>>,
    poll_interval: Duration,
    clock: Clock,
    mut shutdown_rx: Receiver<()>,
) where
    K: Send + Sync + Hash + Eq + 'static,
    V: Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(poll_interval);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    prune_entries( &map, &clock).await;
                }
                _ = &mut shutdown_rx => {
                    return;
                }
            }
        }
    });
}

async fn prune_entries<K, V>(map: &Arc<Map<K, V>>, clock: &Clock)
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    let now_secs = if let Ok(now_secs) = clock.now_relative_secs() {
        now_secs
    } else {
        warn!("Failed to get current time when pruning sessions");
        return;
    };

    let pin = map.inner.pin();
    let expired_keys = pin
        .iter()
        .filter(|(_, value)| value.expiration_secs() <= now_secs);

    for (key, _) in expired_keys {
        map.inner.pin().remove(key);
    }
}

/// A wrapper over functions to generate relative timestamps and ttl.
/// During test it is driven via [`tokio::time`], otherwise it uses system time.
#[derive(Clone)]
struct Clock {
    #[cfg(test)]
    base: Instant,
}

impl Clock {
    fn new() -> Clock {
        #[cfg(not(test))]
        return Clock {};

        #[cfg(test)]
        return Clock {
            base: Instant::now(),
        };
    }

    /// Returns the current time in seconds, relative to some base time instant.
    /// For non test cases, relative to UNIX_EPOCH, while during test, a random
    /// point in the past is used.
    fn now_relative_secs(&self) -> Result<u64, String> {
        #[cfg(not(test))]
        return SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                String::from("duration_since was called with time later than the current time")
            })
            .map(|t| t.as_secs());

        #[cfg(test)]
        return Ok((Instant::now()).duration_since(self.base).as_secs());
    }

    /// Returns the expiration time from now in seconds for the given ttl.
    fn compute_expiration_secs(&self, ttl: Duration) -> Result<u64, String> {
        #[cfg(not(test))]
        return (SystemTime::now() + ttl)
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                String::from("duration_since was called with time later than the current time")
            })
            .map(|t| t.as_secs());

        #[cfg(test)]
        return Ok((Instant::now() + ttl).duration_since(self.base).as_secs());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::endpoint::EndpointAddress;
    use std::net::Ipv4Addr;

    use tokio::time;

    fn address_pair() -> (EndpointAddress, EndpointAddress) {
        (
            (Ipv4Addr::LOCALHOST, 8080).into(),
            ([127, 0, 0, 2], 8080).into(),
        )
    }

    #[tokio::test]
    async fn len() {
        let (one, two) = address_pair();
        const TTL: Duration = Duration::from_millis(50);
        const POLL: Duration = Duration::from_millis(10);

        let map = TtlMap::<EndpointAddress, usize>::new(TTL, POLL);
        map.insert(one, 1);
        assert_eq!(map.len(), 1);
        map.insert(two, 2);
        assert_eq!(map.len(), 2);

        // add POLL to allow for if it JUST polls right before TTL.
        tokio::time::sleep(TTL + POLL).await;
        assert!(map.is_empty());
    }

    #[tokio::test]
    async fn insert_and_get() {
        let (one, two) = address_pair();

        let map = TtlMap::<EndpointAddress, usize>::new(
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert(one.clone(), 1);
        map.insert(two.clone(), 2);

        assert_eq!(map.get(&one).unwrap(), 1);
        assert_eq!(map.get(&two).unwrap(), 2);
    }

    #[tokio::test]
    async fn insert_and_get_expiration() {
        // Test that when we insert or retrieve an item, we update its expiration.
        time::pause();

        let (one, _) = address_pair();

        let map = TtlMap::<EndpointAddress, usize>::new(
            Duration::from_secs(10),
            Duration::from_millis(10),
        );

        map.insert(one.clone(), 1);
        let exp1 = map.0.inner.pin().get(&one).unwrap().expiration_secs();

        time::advance(Duration::from_secs(2)).await;
        let _ = map.get(&one).unwrap();
        let exp2 = map.0.inner.pin().get(&one).unwrap().expiration_secs();

        time::advance(Duration::from_secs(3)).await;
        let _ = map.get(&one).unwrap();
        let exp3 = map.0.inner.pin().get(&one).unwrap().expiration_secs();

        assert!(exp1 < exp2);
        assert_eq!(2, exp2 - exp1);
        assert!(exp2 < exp3);
        assert_eq!(3, exp3 - exp2);
    }

    #[tokio::test]
    async fn contains_key() {
        let (one, two) = address_pair();
        let three = ([127, 0, 0, 3], 8080).into();

        let map = TtlMap::<EndpointAddress, usize>::new(
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert(one.clone(), 1);
        map.insert(two.clone(), 2);

        assert!(map.contains_key(&one));
        assert!(!map.contains_key(&three));
        assert!(map.contains_key(&two));
    }

    #[tokio::test]
    async fn expiration_ttl() {
        // Test that when we expire entries at our configured ttl.
        time::pause();

        let (one, _) = address_pair();

        let ttl = Duration::from_secs(12);
        let map = TtlMap::<EndpointAddress, usize>::new(ttl, Duration::from_millis(10));

        assert!(map.0.inner.pin().get(&one).is_none());
        map.insert(one.clone(), 9);
        let exp = map.0.inner.pin().get(&one).unwrap().expiration_secs();

        // Check that it expires at our configured TTL.
        assert_eq!(12, exp);
    }

    #[tokio::test]
    async fn cleanup_expired_entries() {
        // Test that we delete expired entries from the ttl map.
        time::pause();

        let (one, two) = address_pair();

        let map =
            TtlMap::<EndpointAddress, usize>::new(Duration::from_secs(5), Duration::from_secs(1));
        map.insert(one.clone(), 1);
        map.insert(two.clone(), 2);

        assert!(map.contains_key(&one));
        assert!(map.contains_key(&two));

        time::advance(Duration::from_secs(4)).await;

        // Read one key so that it does not expire at the original ttl.
        let _ = map.get(&two).unwrap();

        // Check that only the un-read key is deleted.
        time::advance(Duration::from_secs(4)).await;
        assert!(!map.contains_key(&one));
        assert!(map.contains_key(&two));
        assert_eq!(map.len(), 1);

        // Check that the second key is eventually deleted.
        time::advance(Duration::from_secs(3)).await;
        assert!(!map.contains_key(&one));
        assert!(!map.contains_key(&two));
        assert_eq!(map.len(), 0);
    }
}
