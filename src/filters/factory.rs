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

use std::sync::Arc;

use crate::{
    config::ConfigType,
    filters::{Error, Filter},
};

/// An owned pointer to a dynamic [`FilterFactory`] instance.
pub type DynFilterFactory = Box<dyn FilterFactory>;

/// The value returned by [`FilterFactory::create_filter`].
#[non_exhaustive]
pub struct FilterInstance {
    /// The configuration used to create the filter.
    pub config: Arc<serde_json::Value>,
    /// The created filter.
    pub filter: Box<dyn Filter>,
}

impl FilterInstance {
    /// Constructs a [`FilterInstance`].
    pub fn new(config: serde_json::Value, filter: Box<dyn Filter>) -> FilterInstance {
        FilterInstance {
            config: Arc::new(config),
            filter,
        }
    }
}

/// Provides the name and creation function for a given [`Filter`].
///
pub trait FilterFactory: Sync + Send {
    /// name returns the configuration name for the Filter
    /// The returned string identifies the filter item's path with the following format:
    ///     `quilkin.filters.<module>.<version>.<item-name>`
    /// where:
    ///     <module>: The rust module name containing the filter item
    ///     <version>: The filter's version.
    ///     <item-name>: The name of the rust item (e.g enum, struct) implementing the filter.
    /// For example the `v1alpha1` version of the debug filter has the name:
    ///     `quilkin.filters.debug_filter.v1alpha1.Debug`
    fn name(&self) -> &'static str;

    /// Returns the schema for the configuration of the [`Filter`].
    fn config_schema(&self) -> schemars::schema::RootSchema;

    /// Returns a filter based on the provided arguments.
    fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error>;

    /// Returns the [`ConfigType`] from the provided Option, otherwise it returns
    /// Error::MissingConfig if the Option is None.
    fn require_config(&self, config: Option<ConfigType>) -> Result<ConfigType, Error> {
        config.ok_or_else(|| Error::MissingConfig(self.name()))
    }
}

/// Arguments needed to create a new filter.
pub struct CreateFilterArgs {
    /// Configuration for the filter.
    pub config: Option<ConfigType>,
}

impl CreateFilterArgs {
    /// Create a new instance of [`CreateFilterArgs`].
    pub fn new(config: Option<ConfigType>) -> CreateFilterArgs {
        Self { config }
    }

    /// Creates a new instance of [`CreateFilterArgs`] using a
    /// fixed [`ConfigType`].
    pub fn fixed(config: Option<serde_json::Value>) -> CreateFilterArgs {
        Self::new(config.map(ConfigType::Static))
    }

    /// Creates a new instance of [`CreateFilterArgs`] using a
    /// dynamic [`ConfigType`].
    pub fn dynamic(config: Option<prost_types::Any>) -> CreateFilterArgs {
        CreateFilterArgs::new(config.map(ConfigType::Dynamic))
    }
}
