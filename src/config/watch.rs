/*
 * Copyright 2022 Google LLC
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

pub mod agones;
mod fs;

pub use self::{agones::watch as agones, fs::watch as fs};

use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct Watch<T: Reconcile> {
    inner: std::sync::Arc<Inner<T>>,
}

impl<T: Reconcile> std::ops::Deref for Watch<T> {
    type Target = Inner<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug)]
pub struct Inner<T: Reconcile> {
    value: T,
    watchers: watch::Sender<T>,
    /// the events that have changed `T`. Used to propagate change events to
    /// delta discovery streams.
    change_events: watch::Sender<Option<ChangeEvent<T::Key, T::Value>>>,
}

impl<T: Clone + Reconcile> Watch<T> {
    pub fn new(value: T) -> Self {
        Self {
            inner: std::sync::Arc::new(Inner {
                watchers: watch::channel(value.clone()).0,
                value: value,
                change_events: watch::channel(None).0,
            }),
        }
    }

    pub fn watch(&self) -> watch::Receiver<T> {
        self.watchers.subscribe()
    }
}

impl<T: Clone + PartialEq + std::fmt::Debug + Reconcile> Watch<T>
    where <T as Reconcile>::Key: Clone,
          <T as Reconcile>::Value: Clone
{
    pub fn read(&self) -> ReadGuard<T> {
        ReadGuard { inner: self }
    }

    pub fn update(&self, key: T::Key, value: T::Value) {
        let version = self.value.update(&key, value.clone());
        let _ = self.watchers.send(self.value.clone());
        let _ = self.change_events.send(Some(ChangeEvent::Update {
            key,
            value,
            version,
        }));
    }

    pub fn delete(&self, key: T::Key) {
        let version = self.value.remove_key(&key);
        let _ = self.watchers.send(self.value.clone());
        let _ = self.change_events.send(Some(ChangeEvent::Delete { key }));
    }

    pub fn delete_value(&self, value: T::Value) {
        let version = self.value.remove_single_value(value.clone());
        let _ = self.watchers.send(self.value.clone());
        let _ = self.change_events.send(Some(ChangeEvent::DeleteValue {
            value,
        }));
    }

    pub fn has_changed(&self) -> bool {
        self.value != *self.watchers.borrow()
    }

    pub fn check_for_changes(&self) {
        if self.has_changed() {
            tracing::debug!(
                watchers = self.watchers.receiver_count(),
                "changed detected"
            );
            self.watchers
                .send_modify(|value| *value = self.value.clone());
        } else {
            tracing::debug!("no change detected");
        }
    }
}

impl<T: serde::Serialize + Reconcile> serde::Serialize for Watch<T> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(ser)
    }
}

impl<T: Default + Clone + Reconcile> Default for Watch<T> {
    fn default() -> Self {
        Watch::new(<_>::default())
    }
}

impl<'de, T: serde::Deserialize<'de> + Clone + Reconcile> serde::Deserialize<'de> for Watch<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <T>::deserialize(deserializer).map(Watch::new)
    }
}

impl<T: schemars::JsonSchema + Reconcile> schemars::JsonSchema for Watch<T> {
    fn schema_name() -> String {
        <T>::schema_name()
    }
    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <T>::json_schema(gen)
    }

    fn is_referenceable() -> bool {
        <T>::is_referenceable()
    }
}

pub struct ReadGuard<'inner, T: Clone + PartialEq + std::fmt::Debug + Reconcile> {
    inner: &'inner Watch<T>,
}

impl<'inner, T: Clone + PartialEq + std::fmt::Debug + Reconcile> Drop for ReadGuard<'inner, T> {
    fn drop(&mut self) {
        debug_assert!(!self.inner.has_changed());
    }
}

impl<'inner, T: Clone + PartialEq + std::fmt::Debug + Reconcile> std::ops::Deref for ReadGuard<'inner, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.inner.value
    }
}

impl<T: PartialEq + Reconcile> PartialEq for Watch<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.inner.value.eq(&rhs.inner.value)
    }
}

impl<T: Eq + Reconcile> Eq for Watch<T> {}

#[derive(Debug, Clone)]
enum ChangeEvent<K, V> {
    Update {
        key: K,
        version: u64,
        value: V,
    },
    Delete {
        key: K,
    },
    DeleteValue {
        value: V,
    },
}

/// A trait over update and remove operations to `Watch` types, this allows
/// for us to easily be generic over change events while allowing the specific
/// type to be responsible for updating itself.
pub trait Reconcile {
    type Key: std::fmt::Debug + Clone;
    type Value: std::fmt::Debug + Clone;
    /// Updates the type with the new value at `K`, returns the new version
    /// number of `K`.
    fn update(&self, key: &Self::Key, value: Self::Value) -> u64;
    /// Removes `K` from the type.
    fn remove_key(&self, key: &Self::Key);
    /// Removes value from all keys.
    fn remove_single_value(&self, value: Self::Value) -> Self::Value;
}
