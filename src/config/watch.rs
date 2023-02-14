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
pub struct Watch<T> {
    value: T,
    watchers: std::sync::Arc<watch::Sender<T>>,
}

impl<T: Clone> Watch<T> {
    pub fn new(value: T) -> Self {
        Self {
            watchers: std::sync::Arc::new(watch::channel(value.clone()).0),
            value,
        }
    }

    pub async fn has_changed(&self) -> Result<(), watch::error::RecvError> {
        self.watchers.subscribe().changed().await
    }
}

impl<T: Clone + PartialEq> Watch<T> {
    pub fn value(&self) -> WatchGuard<T> {
        WatchGuard { inner: self }
    }

    pub fn modify(&self, func: impl Fn(&WatchGuard<T>)) {
        (func)(&WatchGuard { inner: self })
    }

    pub fn check_for_changes(&self) {
        if self.value != *self.watchers.borrow() {
            self.watchers.send_replace(self.value.clone());
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

pub struct WatchGuard<'inner, T: Clone + PartialEq> {
    inner: &'inner Watch<T>,
}

impl<'inner, T: Clone + PartialEq> Drop for WatchGuard<'inner, T> {
    fn drop(&mut self) {
        self.inner.check_for_changes();
    }
}

impl<'inner, T: Clone + PartialEq> std::ops::Deref for WatchGuard<'inner, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner.value
    }
}

impl<T: PartialEq> PartialEq for Watch<T> {
    fn eq(&self, rhs: &Self) -> bool {
        self.value.eq(&rhs.value)
    }
}

impl<T: Eq> Eq for Watch<T> {}
