/*
 * Copyright 2020 Google LLC
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

use dashmap::mapref::entry::Entry as DashMapEntry;
use dashmap::mapref::one::{Ref, RefMut};
use dashmap::DashMap;
use slog::{warn, Logger};
use std::borrow::Borrow;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::time::Instant;

/// A wrapper around the value of an entry in the map.
/// It contains the value's ttl.
pub(crate) struct Value<V> {
    pub value: V,
    expires_at: Arc<AtomicU64>,
    #[cfg(test)]
    clock: TestClock,
    #[cfg(not(test))]
    clock: RealClock,
}

impl<V> Value<V> {
    fn new(
        value: V,
        log: &Logger,
        ttl: Duration,
        #[cfg(test)] clock: TestClock,
        #[cfg(not(test))] clock: RealClock,
    ) -> Value<V> {
        let value = Value {
            value,
            expires_at: Arc::new(AtomicU64::new(0)),
            clock,
        };
        value.update_expiration(log, ttl);
        value
    }

    /// Get the expiration time for this value. The returned value is the
    /// number of seconds relative to some reference point (e.g UNIX_EPOCH), based
    /// on the clock being used.
    fn expiration(&self) -> u64 {
        self.expires_at.load(Ordering::Relaxed)
    }

    /// Update the value's expiration time to (now + TTL).
    fn update_expiration(&self, log: &Logger, ttl: Duration) {
        match self.clock.compute_expiration(ttl) {
            Ok(new_expiration_time) => {
                self.expires_at
                    .store(new_expiration_time, Ordering::Relaxed);
            }
            Err(err) => {
                warn!(log, "failed to increment key expiration: {}", err)
            }
        }
    }
}

/// Map contains the hash map implementation.
struct Map<K, V> {
    inner: DashMap<K, Value<V>>,
    log: Logger,
    ttl: Duration,
    shutdown_tx: Option<Sender<()>>,

    #[cfg(test)]
    clock: TestClock,
    #[cfg(not(test))]
    clock: RealClock,
}

impl<K, V> Drop for Map<K, V> {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            shutdown_tx.send(()).ok();
        }
    }
}

/// TTLMap is a key value hash map where entries are associated with a TTL.
/// When the TTL for an entry elapses, the entry is removed from the map.
/// The TTL is reset each time the entry is (re)inserted or read via [`TTLMap::get`],
/// [`TTLMap::get_mut`] functions, or via the [`TTLMap::entry`] interface.
/// During tests, the internal clock implementation is driven by [`tokio::time`] so
/// functions like [`tokio::time::pause`] and [`tokio::time::advance`] can be used.
#[derive(Clone)]
pub(crate) struct TTLMap<K, V>(Arc<Map<K, V>>);

impl<K, V> TTLMap<K, V>
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    pub fn new(log: Logger, ttl: Duration, poll_interval: Duration) -> Self {
        Self::initialize(log, DashMap::new(), ttl, poll_interval)
    }

    #[allow(dead_code)]
    pub fn with_capacity(
        log: Logger,
        ttl: Duration,
        poll_interval: Duration,
        capacity: usize,
    ) -> Self {
        Self::initialize(log, DashMap::with_capacity(capacity), ttl, poll_interval)
    }

    fn initialize(
        log: Logger,
        inner: DashMap<K, Value<V>>,
        ttl: Duration,
        poll_interval: Duration,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = channel();
        let map = TTLMap(Arc::new(Map {
            inner,
            shutdown_tx: Some(shutdown_tx),
            log: log.clone(),
            ttl,

            #[cfg(test)]
            clock: TestClock(Instant::now()),
            #[cfg(not(test))]
            clock: RealClock,
        }));
        spawn_cleanup_task(
            log,
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
    pub(crate) fn now_secs(&self) -> u64 {
        self.0.clock.now().unwrap_or_default()
    }
}

impl<K, V> TTLMap<K, V>
where
    K: Eq + Hash + Send + Sync,
    V: Send + Sync,
{
    #[allow(dead_code)]
    /// Returns a reference to value corresponding to key.
    pub fn get<Q>(&self, key: &Q) -> Option<Ref<K, Value<V>>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let value = self.0.inner.get(key);
        if let Some(ref value) = value {
            value.update_expiration(&self.0.log, self.0.ttl)
        }

        value
    }

    #[allow(dead_code)]
    /// Returns a mutable reference to value corresponding to key.
    /// The value will be reset to expire at the configured TTL after the time of retrieval.
    pub fn get_mut<Q>(&self, key: &Q) -> Option<RefMut<K, Value<V>>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let value = self.0.inner.get_mut(key);
        if let Some(ref value) = value {
            value.update_expiration(&self.0.log, self.0.ttl);
        }

        value
    }

    #[allow(dead_code)]
    /// Returns the number of entries in the map.
    /// The value will be reset to expire at the configured TTL after the time of retrieval.
    pub fn len(&self) -> usize {
        self.0.inner.len()
    }

    #[allow(dead_code)]
    /// Returns true if the map contains a value for the specified key.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.inner.contains_key(key)
    }

    #[allow(dead_code)]
    /// Inserts a key-value pair into the map.
    /// The value will be set to expire at the configured TTL after the time of insertion.
    /// If a previous value existed for this key, that value is returned.
    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.0
            .inner
            .insert(
                key,
                Value::new(value, &self.0.log, self.0.ttl, self.0.clock.clone()),
            )
            .map(|value| value.value)
    }

    /// Returns an API for in-place updates of the specified key-value pair.
    /// Note: This acquires a write lock on the map's shard that corresponds
    /// to the entry.
    pub fn entry(&self, key: K) -> Entry<K, Value<V>> {
        let log = &self.0.log;
        let ttl = self.0.ttl;
        match self.0.inner.entry(key) {
            inner @ DashMapEntry::Occupied(_) => Entry::Occupied(OccupiedEntry {
                inner,
                log,
                ttl,
                clock: self.0.clock.clone(),
            }),
            inner @ DashMapEntry::Vacant(_) => Entry::Vacant(VacantEntry {
                inner,
                log,
                ttl,
                clock: self.0.clock.clone(),
            }),
        }
    }
}

/// A view into an occupied entry in the map.
pub(crate) struct OccupiedEntry<'a, K, V> {
    inner: DashMapEntry<'a, K, V>,
    log: &'a Logger,
    ttl: Duration,
    #[cfg(test)]
    clock: TestClock,
    #[cfg(not(test))]
    clock: RealClock,
}

/// A view into a vacant entry in the map.
pub(crate) struct VacantEntry<'a, K, V> {
    inner: DashMapEntry<'a, K, V>,
    log: &'a Logger,
    ttl: Duration,
    #[cfg(test)]
    clock: TestClock,
    #[cfg(not(test))]
    clock: RealClock,
}

/// A view into an entry in the map.
/// It may either be [`VacantEntry`] or [`OccupiedEntry`]
pub(crate) enum Entry<'a, K, V> {
    Occupied(OccupiedEntry<'a, K, V>),
    Vacant(VacantEntry<'a, K, V>),
}

impl<'a, K, V> OccupiedEntry<'a, K, Value<V>>
where
    K: Eq + Hash,
{
    /// Returns a reference to the entry's value.
    /// The value will be reset to expire at the configured TTL after the time of retrieval.
    pub fn get(&self) -> &Value<V> {
        match &self.inner {
            DashMapEntry::Occupied(entry) => {
                let value = entry.get();
                value.update_expiration(self.log, self.ttl);
                value
            }
            _ => unreachable!("BUG: entry type should be occupied"),
        }
    }

    #[allow(dead_code)]
    /// Returns a mutable reference to the entry's value.
    /// The value will be reset to expire at the configured TTL after the time of retrieval.
    pub fn get_mut(&mut self) -> &mut Value<V> {
        match &mut self.inner {
            DashMapEntry::Occupied(entry) => {
                let value = entry.get_mut();
                value.update_expiration(self.log, self.ttl);
                value
            }
            _ => unreachable!("BUG: entry type should be occupied"),
        }
    }

    #[allow(dead_code)]
    /// Replace the entry's value with a new value, returning the old value.
    /// The value will be set to expire at the configured TTL after the time of insertion.
    pub fn insert(&mut self, value: V) -> Value<V> {
        match &mut self.inner {
            DashMapEntry::Occupied(entry) => {
                entry.insert(Value::new(value, self.log, self.ttl, self.clock.clone()))
            }
            _ => unreachable!("BUG: entry type should be occupied"),
        }
    }
}

impl<'a, K, V> VacantEntry<'a, K, Value<V>>
where
    K: Eq + Hash,
{
    /// Set an entry's value.
    /// The value will be set to expire at the configured TTL after the time of insertion.
    pub fn insert(self, value: V) -> RefMut<'a, K, Value<V>> {
        match self.inner {
            DashMapEntry::Vacant(entry) => {
                entry.insert(Value::new(value, self.log, self.ttl, self.clock.clone()))
            }
            _ => unreachable!("BUG: entry type should be vacant"),
        }
    }
}

fn spawn_cleanup_task<K, V>(
    log: Logger,
    map: Arc<Map<K, V>>,
    poll_interval: Duration,
    #[cfg(test)] clock: TestClock,
    #[cfg(not(test))] clock: RealClock,
    mut shutdown_rx: Receiver<()>,
) where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    let mut interval = tokio::time::interval(poll_interval);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    prune_sessions(&log, &map, &clock).await;
                }
                _ = &mut shutdown_rx => {
                    return;
                }
            }
        }
    });
}

async fn prune_sessions<K, V>(
    log: &Logger,
    map: &Arc<Map<K, V>>,
    #[cfg(test)] clock: &TestClock,
    #[cfg(not(test))] clock: &RealClock,
) where
    K: Eq + Hash + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    let now = if let Ok(now) = clock.now() {
        now
    } else {
        warn!(log, "Failed to get current time when pruning sessions");
        return;
    };

    // Take a read lock first and check if there is at least 1 item to remove.
    let has_expired_keys = map
        .inner
        .iter()
        .filter(|entry| entry.value().expiration() <= now)
        .take(1)
        .next()
        .is_some();

    // If we have work to do then, take a write lock.
    if has_expired_keys {
        // Go over the whole map in case anything expired
        // since acquiring the write lock.
        map.inner.retain(|_, value| value.expiration() > now);
    }
}

// The cfg attribute isn't working nicely with clippy so silence the unused warning.
#[allow(dead_code)]
/// A wrapper over functions to generate relative timestamps via tokio::time.
#[derive(Clone)]
struct TestClock(Instant);
impl TestClock {
    #[allow(dead_code)]
    fn compute_expiration(&self, ttl: Duration) -> Result<u64, String> {
        Ok((Instant::now() + ttl).duration_since(self.0).as_secs())
    }

    #[allow(dead_code)]
    fn now(&self) -> Result<u64, String> {
        Ok((Instant::now()).duration_since(self.0).as_secs())
    }
}

// The cfg attribute isn't working nicely with clippy so silence the unused warning.
#[allow(dead_code)]
/// A wrapper to generate relative timestamps using system time.
#[derive(Clone)]
struct RealClock;
impl RealClock {
    #[allow(dead_code)]
    fn compute_expiration(&self, ttl: Duration) -> Result<u64, String> {
        (SystemTime::now() + ttl)
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                String::from("duration_since was called with time later than the current time")
            })
            .map(|t| t.as_secs())
    }

    #[allow(dead_code)]
    fn now(&self) -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                String::from("duration_since was called with time later than the current time")
            })
            .map(|t| t.as_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::logger;
    use tokio::time;

    #[tokio::test]
    async fn len() {
        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);
        assert_eq!(map.len(), 1);
        map.insert("two".into(), 2);
        assert_eq!(map.len(), 2);
    }

    #[tokio::test]
    async fn insert_and_get() {
        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);
        map.insert("two".into(), 2);

        assert_eq!(map.get("one").unwrap().value, 1);
        assert_eq!(map.get("two").unwrap().value, 2);
    }

    #[tokio::test]
    async fn insert_and_get_expiration() {
        // Test that when we insert or retrieve an item, we update its expiration.
        time::pause();
        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);

        let exp1 = map.get("one").unwrap().expiration();

        time::advance(Duration::from_secs(2)).await;
        let exp2 = map.get("one").unwrap().expiration();

        time::advance(Duration::from_secs(3)).await;
        let exp3 = map.get("one").unwrap().expiration();

        assert!(exp1 < exp2);
        assert_eq!(2, exp2 - exp1);
        assert!(exp2 < exp3);
        assert_eq!(3, exp3 - exp2);
    }

    #[tokio::test]
    async fn contains_key() {
        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);
        map.insert("two".into(), 2);

        assert!(map.contains_key("one"));
        assert!(!map.contains_key("three"));
        assert!(map.contains_key("two"));
    }

    #[tokio::test]
    async fn entry_occupied_insert_and_get() {
        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);

        match map.entry("one".into()) {
            Entry::Occupied(mut entry) => {
                assert_eq!(entry.get().value, 1);
                entry.insert(5);
            }
            _ => unreachable!("expected occupied entry"),
        }

        assert_eq!(map.get("one").unwrap().value, 5);
    }

    #[tokio::test]
    async fn entry_occupied_get_mut() {
        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);

        match map.entry("one".into()) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().value = 5;
            }
            _ => unreachable!("expected occupied entry"),
        }

        assert_eq!(map.get("one").unwrap().value, 5);
    }

    #[tokio::test]
    async fn entry_vacant_insert() {
        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );

        match map.entry("one".into()) {
            Entry::Vacant(entry) => {
                let mut e = entry.insert(1);
                assert_eq!(e.value, 1);
                e.value = 5;
            }
            _ => unreachable!("expected occupied entry"),
        }

        assert_eq!(map.get("one").unwrap().value, 5);
    }

    #[tokio::test]
    async fn entry_occupied_get_expiration() {
        // Test that when we get a value via OccupiedEntry, we update its expiration.
        time::pause();

        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);

        let exp1 = map.get("one").unwrap().expiration();

        time::advance(Duration::from_secs(2)).await;

        let exp2 = match map.entry("one".into()) {
            Entry::Occupied(entry) => entry.get().expiration(),
            _ => unreachable!("expected occupied entry"),
        };

        assert!(exp1 < exp2);
        assert_eq!(2, exp2 - exp1);
    }

    #[tokio::test]
    async fn entry_occupied_get_mut_expiration() {
        // Test that when we get_mut a value via OccupiedEntry, we update its expiration.
        time::pause();

        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);

        let exp1 = map.get("one").unwrap().expiration();

        time::advance(Duration::from_secs(2)).await;

        let exp2 = match map.entry("one".into()) {
            Entry::Occupied(mut entry) => entry.get_mut().expiration(),
            _ => unreachable!("expected occupied entry"),
        };

        assert!(exp1 < exp2);
        assert_eq!(2, exp2 - exp1);
    }

    #[tokio::test]
    async fn entry_occupied_insert_expiration() {
        // Test that when we replace a value via OccupiedEntry, we update its expiration.
        time::pause();

        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        map.insert("one".into(), 1);

        let exp1 = map.get("one").unwrap().expiration();

        time::advance(Duration::from_secs(2)).await;

        let old_exp1 = match map.entry("one".into()) {
            Entry::Occupied(mut entry) => entry.insert(9).expiration(),
            _ => unreachable!("expected occupied entry"),
        };

        let exp2 = map.get("one").unwrap().expiration();

        assert_eq!(exp1, old_exp1);
        assert!(exp1 < exp2);
        assert_eq!(2, exp2 - exp1);
    }

    #[tokio::test]
    async fn entry_occupied_vacant_expiration() {
        // Test that when we insert a value via VacantEntry, we update its expiration.
        time::pause();

        let map = TTLMap::<String, usize>::new(
            logger(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );

        let exp1 = match map.entry("one".into()) {
            Entry::Vacant(entry) => entry.insert(9).expiration(),
            _ => unreachable!("expected vacant entry"),
        };

        time::advance(Duration::from_secs(2)).await;

        let exp2 = map.get("one").unwrap().expiration();

        // Initial expiration should be set at our configured ttl.
        assert_eq!(10, exp1);

        assert!(exp1 < exp2);
        assert_eq!(2, exp2 - exp1);
    }

    #[tokio::test]
    async fn expiration_ttl() {
        // Test that when we expire entries at our configured ttl.
        time::pause();

        let ttl = Duration::from_secs(12);
        let map = TTLMap::<String, usize>::new(logger(), ttl, Duration::from_millis(10));

        let exp = match map.entry("one".into()) {
            Entry::Vacant(entry) => entry.insert(9).expiration(),
            _ => unreachable!("expected vacant entry"),
        };

        // Check that it expires at our configured TTL.
        assert_eq!(12, exp);
    }

    #[tokio::test]
    async fn cleanup_expired_entries() {
        // Test that we delete expired entries from the ttl map.
        time::pause();

        let map =
            TTLMap::<String, usize>::new(logger(), Duration::from_secs(5), Duration::from_secs(1));
        map.insert("one".into(), 1);
        map.insert("two".into(), 2);

        assert!(map.contains_key("one"));
        assert!(map.contains_key("two"));

        time::advance(Duration::from_secs(4)).await;

        // Read one key so that it does not expire at the original ttl.
        let _ = map.get("two").unwrap();

        // Check that only the un-read key is deleted.
        time::advance(Duration::from_secs(4)).await;
        assert!(!map.contains_key("one"));
        assert!(map.contains_key("two"));
        assert_eq!(map.len(), 1);

        // Check that the second key is eventually deleted.
        time::advance(Duration::from_secs(3)).await;
        assert!(!map.contains_key("one"));
        assert!(!map.contains_key("two"));
        assert_eq!(map.len(), 0);
    }
}
