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
use std::sync::Arc;

use tokio::sync::watch;

#[derive(Clone, Debug)]
pub struct Watch<T> {
    value: Arc<T>,
    watchers: Arc<watch::Sender<Arc<T>>>,
}

impl<T> Watch<T> {
    pub fn new(value: T) -> Self {
        let value = Arc::new(value);
        Self {
            watchers: Arc::new(watch::channel(value.clone()).0),
            value,
        }
    }

    #[inline]
    pub fn watch(&self) -> watch::Receiver<Arc<T>> {
        self.watchers.subscribe()
    }

    #[inline]
    pub fn clone_value(&self) -> Arc<T> {
        self.value.clone()
    }
}

#[derive(Clone, Copy)]
pub enum Marker {
    Version(u64),
}

pub trait Watchable {
    fn mark(&self) -> Marker;
    fn has_changed(&self, marker: Marker) -> bool;
}

impl<T: Watchable + std::fmt::Debug> Watch<T> {
    pub fn read(&self) -> ReadGuard<T> {
        ReadGuard {
            inner: self,
            marker: self.value.mark(),
        }
    }

    pub fn write(&self) -> WatchGuard<T> {
        WatchGuard {
            inner: self,
            marker: self.value.mark(),
        }
    }

    #[inline]
    pub fn modify<R>(&self, func: impl FnOnce(&WatchGuard<T>) -> R) -> R {
        (func)(&WatchGuard {
            inner: self,
            marker: self.value.mark(),
        })
    }

    #[inline]
    fn has_changed(&self, marker: Marker) -> bool {
        self.value.has_changed(marker)
    }

    fn check_for_changes(&self, marker: Marker) {
        if self.has_changed(marker) {
            tracing::trace!(watchers = self.watchers.receiver_count(), "change detected");
            self.watchers
                .send_modify(|value| *value = self.value.clone());
        } else {
            tracing::trace!("no change detected");
        }
    }
}

impl<T: serde::Serialize> serde::Serialize for Watch<T> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        self.value.serialize(ser)
    }
}

impl<T: Default + Clone> Default for Watch<T> {
    fn default() -> Self {
        Watch::new(<_>::default())
    }
}

impl<'de, T: serde::Deserialize<'de> + Clone> serde::Deserialize<'de> for Watch<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <T>::deserialize(deserializer).map(Watch::new)
    }
}

impl<T: schemars::JsonSchema> schemars::JsonSchema for Watch<T> {
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

pub struct ReadGuard<'inner, T: Watchable + std::fmt::Debug> {
    inner: &'inner Watch<T>,
    marker: Marker,
}

impl<'inner, T: Watchable + std::fmt::Debug> Drop for ReadGuard<'inner, T> {
    fn drop(&mut self) {
        debug_assert!(!self.inner.has_changed(self.marker));
    }
}

impl<'inner, T: Watchable + std::fmt::Debug> std::ops::Deref for ReadGuard<'inner, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.value
    }
}

pub struct WatchGuard<'inner, T: Watchable + std::fmt::Debug> {
    inner: &'inner Watch<T>,
    marker: Marker,
}

impl<'inner, T: Watchable + std::fmt::Debug> Drop for WatchGuard<'inner, T> {
    fn drop(&mut self) {
        self.inner.check_for_changes(self.marker);
    }
}

impl<'inner, T: Watchable + std::fmt::Debug> std::ops::Deref for WatchGuard<'inner, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.value
    }
}

#[cfg(test)]
impl<T: PartialEq> PartialEq for Watch<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.value.eq(&rhs.value)
    }
}

#[cfg(test)]
impl<T: Eq> Eq for Watch<T> {}
