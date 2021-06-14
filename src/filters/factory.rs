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

use prometheus::Registry;

use crate::{
    config::ConfigType,
    filters::{Error, Filter},
};

/// An owned pointer to a dynamic [`FilterFactory`] instance.
pub type DynFilterFactory = Box<dyn FilterFactory>;

/// Provides the name and creation function for a given [`Filter`].
///
/// An implementation of [`FilterFactory`] provides a `name` and
/// `create_filter` method.
///
/// - The `create_filter` method takes in [configuration][filter configuration]
///   for the filter to create and returns a new instance of its filter type.
/// - The `name` method returns the unique identifier of the filter.
pub trait FilterFactory: Sync + Send {
    /// name returns the configuration name for the Filter
    /// The returned string identifies the filter item's path with the following format:
    ///     `quilkin.extensions.filters.<module>.<version>.<item-name>`
    /// where:
    ///     <module>: The rust module name containing the filter item
    ///     <version>: The filter's version.
    ///     <item-name>: The name of the rust item (e.g enum, struct) implementing the filter.
    /// For example the `v1alpha1` version of the debug filter has the name:
    ///     `quilkin.extensions.filters.debug_filter.v1alpha1.Debug`
    fn name(&self) -> &'static str;

    /// Returns a filter based on the provided arguments.
    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error>;

    /// Returns the [`ConfigType`] from the provided Option, otherwise it returns
    /// Error::MissingConfig if the Option is None.
    fn require_config<'a, 'b>(
        &'a self,
        config: Option<ConfigType<'b>>,
    ) -> Result<ConfigType<'b>, Error> {
        config.ok_or_else(|| Error::MissingConfig(self.name()))
    }
}

/// Arguments needed to create a new filter.
pub struct CreateFilterArgs<'a> {
    /// Configuration for the filter.
    pub config: Option<ConfigType<'a>>,
    /// metrics_registry is used to register filter metrics collectors.
    pub metrics_registry: Registry,
}

impl CreateFilterArgs<'_> {
    /// Creates a new instance of [`CreateFilterArgs`] using a
    /// fixed [`ConfigType`].
    pub fn fixed(
        metrics_registry: Registry,
        config: Option<&serde_yaml::Value>,
    ) -> CreateFilterArgs {
        CreateFilterArgs {
            config: config.map(|config| ConfigType::Static(config)),
            metrics_registry,
        }
    }

    /// Creates a new instance of [`CreateFilterArgs`] using a
    /// dynamic [`ConfigType`].
    pub fn dynamic(
        metrics_registry: Registry,
        config: Option<prost_types::Any>,
    ) -> CreateFilterArgs<'static> {
        CreateFilterArgs {
            config: config.map(ConfigType::Dynamic),
            metrics_registry,
        }
    }

    /// Consumes `self` and returns a new instance of [`Self`] using
    /// `metrics_registry` for metrics.
    pub(crate) fn with_metrics_registry(self, metrics_registry: Registry) -> Self {
        CreateFilterArgs {
            metrics_registry,
            ..self
        }
    }
}
