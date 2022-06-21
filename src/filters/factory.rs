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
    filters::{Error, Filter, StaticFilter},
};

/// An owned pointer to a dynamic [`FilterFactory`] instance.
pub type DynFilterFactory = Box<dyn FilterFactory>;

/// The value returned by [`FilterFactory::create_filter`].
#[derive(Clone)]
#[non_exhaustive]
pub struct FilterInstance {
    /// The configuration used to create the filter.
    pub config: Arc<serde_json::Value>,
    /// The created filter.
    pub filter: Arc<dyn Filter>,
}

impl FilterInstance {
    /// Constructs a [`FilterInstance`].
    pub fn new(config: serde_json::Value, filter: Arc<dyn Filter>) -> FilterInstance {
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

    /// Converts YAML configuration into its Protobuf equivalvent.
    fn encode_config_to_protobuf(&self, args: serde_json::Value)
        -> Result<prost_types::Any, Error>;

    /// Converts YAML configuration into its Protobuf equivalvent.
    fn encode_config_to_json(&self, args: prost_types::Any) -> Result<serde_json::Value, Error>;

    /// Returns the [`ConfigType`] from the provided Option, otherwise it returns
    /// Error::MissingConfig if the Option is None.
    fn require_config(&self, config: Option<ConfigType>) -> Result<ConfigType, Error> {
        config.ok_or_else(|| Error::MissingConfig(self.name()))
    }
}

impl<F> FilterFactory for std::marker::PhantomData<fn() -> F>
where
    F: StaticFilter + 'static,
    Error: From<<F::Configuration as TryFrom<F::BinaryConfiguration>>::Error>
        + From<<F::BinaryConfiguration as TryFrom<F::Configuration>>::Error>,
{
    fn name(&self) -> &'static str {
        F::NAME
    }

    fn config_schema(&self) -> schemars::schema::RootSchema {
        schemars::schema_for!(F::Configuration)
    }

    /// Returns a filter based on the provided arguments.
    fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
        let (config_json, config): (_, Option<F::Configuration>) = if let Some(config) = args.config
        {
            config
                .deserialize::<F::Configuration, F::BinaryConfiguration>(self.name())
                .map(|(j, c)| (j, Some(c)))?
        } else {
            (serde_json::Value::Null, None)
        };

        Ok(FilterInstance::new(
            config_json,
            Arc::from(F::try_from_config(config)?),
        ))
    }

    fn encode_config_to_protobuf(
        &self,
        config: serde_json::Value,
    ) -> Result<prost_types::Any, Error> {
        let config: F::Configuration = serde_json::from_value(config)?;

        Ok(prost_types::Any {
            type_url: self.name().into(),
            value: crate::prost::encode::<F::BinaryConfiguration>(&config.try_into()?)?,
        })
    }

    fn encode_config_to_json(&self, config: prost_types::Any) -> Result<serde_json::Value, Error> {
        if self.name() != config.type_url {
            return Err(crate::filters::Error::MismatchedTypes {
                expected: self.name().into(),
                actual: config.type_url,
            });
        }

        let message = <F::BinaryConfiguration as prost::Message>::decode(&*config.value)?;
        let config = F::Configuration::try_from(message)?;

        Ok(serde_json::to_value(&config)?)
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
