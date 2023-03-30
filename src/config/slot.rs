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

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use schemars::JsonSchema;

use crate::filters::prelude::*;

/// A mutable memory location with atomic storage rules.
#[derive(Clone)]
pub struct Slot<T> {
    inner: Arc<ArcSwapOption<T>>,
    #[allow(clippy::type_complexity)]
    watcher: Arc<ArcSwapOption<Box<dyn Fn(&T) + Send + Sync>>>,
}

impl<T> Slot<T> {
    /// Creates a new slot for `value`.
    pub fn new(value: impl Into<Option<T>>) -> Self {
        Self {
            inner: Arc::new(ArcSwapOption::new(value.into().map(Arc::new))),
            watcher: <_>::default(),
        }
    }

    /// Creates a new empty slot.
    pub fn empty() -> Self {
        Self::new(None)
    }

    /// Adds a watcher to to the slot. The watcher will fire whenever slot's
    /// value changes.
    pub fn watch(&self, watcher: impl Fn(&T) + Send + Sync + 'static) {
        tracing::trace!("Adding new watcher");
        self.watcher.store(Some(Arc::new(Box::new(watcher))));
    }

    /// Returns whether any data is present in the slot.
    pub fn is_some(&self) -> bool {
        self.inner.load().is_some()
    }
}

impl<T: Default> Slot<T> {
    /// Creates a new slot containing the default instance of `T`.
    pub fn with_default() -> Self {
        Self::new(T::default())
    }

    /// Triggers the `watcher` function, if present.
    fn call_watcher(&self) {
        if let Some(watcher) = &*self.watcher.load() {
            tracing::trace!("calling watcher");
            (watcher)(&self.load());
        }
    }

    /// Provides a reference to the underlying data.
    pub fn load(&self) -> Arc<T> {
        self.inner.load_full().unwrap_or_default()
    }

    fn store_opt(&self, value: Option<Arc<T>>) {
        tracing::trace!("storing new value");
        self.inner.store(value);
        self.call_watcher();
    }

    /// Replaces the data in the slot with `value`.
    pub fn store(&self, value: Arc<T>) {
        self.store_opt(Some(value));
    }

    /// Removes any data from the slot.
    pub fn remove(&self) {
        self.store_opt(None);
    }

    /// Replaces the data if the slot is empty.
    pub fn store_if_unset(&self, value: Arc<T>) {
        if self.inner.load().is_none() {
            self.store(value);
        }
    }
}

impl<T: Default + PartialEq> Slot<T> {
    /// Replaces the current data in the slot with `value`'s data, if present.
    pub fn try_replace(&self, value: Self) {
        if let Some(value) = value
            .inner
            .load_full()
            .filter(|value| &self.load() != value)
        {
            self.store(value);
        }
    }
}

impl<T: Clone + Default> Slot<T> {
    /// Provides a view into a mutable reference of the current data in the
    /// slot. Any changes made will update the value in the slot.
    pub fn modify(&self, mut modify: impl FnMut(&mut T)) {
        self.inner.rcu(|value| {
            let mut current = value
                .as_deref()
                .map(|value| T::clone(value))
                .unwrap_or_default();
            (modify)(&mut current);
            Some(Arc::new(current))
        });
        self.call_watcher();
    }
}

impl<T: Default> Default for Slot<T> {
    fn default() -> Self {
        Self {
            inner: Arc::new(ArcSwapOption::new(Some(Default::default()))),
            watcher: <_>::default(),
        }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Slot<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.inner.load().fmt(f)
    }
}

impl<T: PartialEq> PartialEq for Slot<T> {
    fn eq(&self, rhs: &Self) -> bool {
        *self.inner.load() == *rhs.inner.load()
    }
}

impl<T> From<T> for Slot<T> {
    fn from(data: T) -> Self {
        Self::new(data)
    }
}

impl<T> From<Option<T>> for Slot<T> {
    fn from(data: Option<T>) -> Self {
        Self::new(data)
    }
}

impl<T: serde::Serialize> serde::Serialize for Slot<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.load().serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Slot<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        <Option<T>>::deserialize(deserializer).map(Slot::new)
    }
}

impl<T: JsonSchema + Default> JsonSchema for Slot<T> {
    fn schema_name() -> String {
        <Option<T>>::schema_name()
    }
    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <Option<T>>::json_schema(gen)
    }

    fn is_referenceable() -> bool {
        <Option<T>>::is_referenceable()
    }
}

#[async_trait::async_trait]
impl<T: crate::filters::Filter + Default> crate::filters::Filter for Slot<T> {
    async fn read(&self, ctx: &mut ReadContext) -> Result<(), FilterError> {
        self.load().read(ctx).await
    }

    async fn write(&self, ctx: &mut WriteContext) -> Result<(), FilterError> {
        self.load().write(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch() {
        static BOOLEAN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        let slot = Slot::new(false);

        slot.watch(|_| {
            BOOLEAN.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        slot.store(Arc::new(true));

        assert_eq!(
            BOOLEAN.load(std::sync::atomic::Ordering::SeqCst),
            *slot.load()
        );
    }
}
