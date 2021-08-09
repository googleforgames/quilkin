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

use std::any::Any;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;

use bytes::Bytes;
use prometheus::{Error as MetricsError, Registry};

use crate::cluster::Endpoint;
use crate::config::{UpstreamEndpoints, ValidationError};
use crate::extensions::filters::ConvertProtoConfigError;
use std::sync::Arc;

/// DynamicMetadata contains shared state between filters during processing for a single packet.
type DynamicMetadata = HashMap<Arc<String>, Box<dyn Any + Send>>;

/// Contains the input arguments to [`Filter::read`].
pub struct ReadContext {
    /// The upstream endpoints that the packet will be forwarded to.
    pub endpoints: UpstreamEndpoints,
    /// The source of the received packet.
    pub from: SocketAddr,
    /// Contents of the received packet.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another
    pub metadata: DynamicMetadata,
    // Enforce using constructor to create this struct.
    phantom: PhantomData<()>,
}

/// Contains the output of [`Filter::read`].
///
/// New instances are created from a [`ReadContext`]
///
/// ```rust
/// # use quilkin::extensions::{ReadContext, ReadResponse};
///   fn read(ctx: ReadContext) -> Option<ReadResponse> {
///       Some(ctx.into())
///   }
/// ```
pub struct ReadResponse {
    /// The upstream endpoints that the packet should be forwarded to.
    pub endpoints: UpstreamEndpoints,
    /// Contents of the packet to be forwarded.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another
    pub metadata: DynamicMetadata,
    // Enforce using constructor to create this struct.
    phantom: PhantomData<()>,
}

/// Contains the input arguments to [`Filter::write`].
pub struct WriteContext<'a> {
    /// The upstream endpoint that we're expecting packets from.
    pub endpoint: &'a Endpoint,
    /// The source of the received packet.
    pub from: SocketAddr,
    /// The destination of the received packet.
    pub to: SocketAddr,
    /// Contents of the received packet.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another
    pub metadata: HashMap<String, Box<dyn Any + Send>>,
    // Enforce using constructor to create this struct.
    phantom: PhantomData<()>,
}

/// Contains the output of [`Filter::write`].
///
/// New instances are created from an [`WriteContext`]
///
/// ```rust
/// # use quilkin::extensions::{WriteContext, WriteResponse};
///   fn write(ctx: WriteContext) -> Option<WriteResponse> {
///       Some(ctx.into())
///   }
/// ```
pub struct WriteResponse {
    /// Contents of the packet to be sent back to the original sender.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another
    pub metadata: HashMap<String, Box<dyn Any + Send>>,
    // Enforce using constructor to create this struct.
    phantom: PhantomData<()>,
}

impl ReadContext {
    /// Creates a new [`ReadContext`]
    pub fn new(endpoints: UpstreamEndpoints, from: SocketAddr, contents: Vec<u8>) -> Self {
        Self {
            endpoints,
            from,
            contents,
            metadata: HashMap::new(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`ReadContext`] from a [`ReadResponse`]
    pub fn with_response(from: SocketAddr, response: ReadResponse) -> Self {
        Self {
            endpoints: response.endpoints,
            from,
            contents: response.contents,
            metadata: response.metadata,
            phantom: PhantomData,
        }
    }
}

impl From<ReadContext> for ReadResponse {
    fn from(ctx: ReadContext) -> Self {
        Self {
            endpoints: ctx.endpoints,
            contents: ctx.contents,
            metadata: ctx.metadata,
            phantom: ctx.phantom,
        }
    }
}

impl WriteContext<'_> {
    /// Creates a new [`WriteContext`]
    pub fn new(
        endpoint: &Endpoint,
        from: SocketAddr,
        to: SocketAddr,
        contents: Vec<u8>,
    ) -> WriteContext {
        WriteContext {
            endpoint,
            from,
            to,
            contents,
            metadata: HashMap::new(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`WriteContext`] from a [`WriteResponse`]
    pub fn with_response(
        endpoint: &Endpoint,
        from: SocketAddr,
        to: SocketAddr,
        response: WriteResponse,
    ) -> WriteContext {
        WriteContext {
            endpoint,
            from,
            to,
            contents: response.contents,
            metadata: response.metadata,
            phantom: PhantomData,
        }
    }
}

impl From<WriteContext<'_>> for WriteResponse {
    fn from(ctx: WriteContext) -> Self {
        Self {
            contents: ctx.contents,
            phantom: ctx.phantom,
            metadata: ctx.metadata,
        }
    }
}

/// Filter is a trait for routing and manipulating packets.
pub trait Filter: Send + Sync {
    /// Read is invoked when the proxy receives data from a downstream connection on the
    /// listening port.
    /// This function should return a [`ReadResponse`] containing the array of
    /// endpoints that the packet should be sent to and the packet that should be
    /// sent (which may be manipulated) as well.
    /// If the packet should be rejected, return None.
    /// By default, passes the context through unchanged
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        Some(ctx.into())
    }

    /// Write is invoked when the proxy is about to send data to a downstream connection
    /// via the listening port after receiving it via one of the upstream Endpoints.
    /// This function should return an [`WriteResponse`] containing the packet to
    /// be sent (which may be manipulated).
    /// If the packet should be rejected, return None.
    /// By default, passes the context through unchanged
    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        Some(ctx.into())
    }
}

#[derive(Debug, PartialEq)]
/// Error is an error when attempting to create a Filter from_config() from a FilterFactory
pub enum Error {
    NotFound(String),
    MissingConfig(String),
    FieldInvalid { field: String, reason: String },
    DeserializeFailed(String),
    InitializeMetricsFailed(String),
    ConvertProtoConfig(ConvertProtoConfigError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound(key) => write!(f, "filter {} is not found", key),
            Error::MissingConfig(filter_name) => {
                write!(f, "filter `{}` requires a configuration", filter_name)
            }
            Error::FieldInvalid { field, reason } => {
                write!(f, "field {} is invalid: {}", field, reason)
            }
            Error::DeserializeFailed(reason) => write!(f, "Deserialization failed: {}", reason),
            Error::InitializeMetricsFailed(reason) => {
                write!(f, "failed to initialize metrics: {}", reason)
            }
            Error::ConvertProtoConfig(inner) => write!(f, "{}", inner),
        }
    }
}

impl From<Error> for ValidationError {
    fn from(error: Error) -> Self {
        Self::FilterInvalid(error)
    }
}

impl From<MetricsError> for Error {
    fn from(error: MetricsError) -> Self {
        Error::InitializeMetricsFailed(error.to_string())
    }
}

pub enum ConfigType<'a> {
    Static(&'a serde_yaml::Value),
    Dynamic(prost_types::Any),
}

impl ConfigType<'_> {
    /// Deserializes a config based on the input type.
    pub fn deserialize<T, P>(self, filter_name: &str) -> Result<T, Error>
    where
        P: prost::Message + Default,
        T: for<'de> serde::Deserialize<'de> + TryFrom<P, Error = ConvertProtoConfigError>,
    {
        match self {
            ConfigType::Static(config) => serde_yaml::to_string(config)
                .and_then(|raw_config| serde_yaml::from_str(raw_config.as_str()))
                .map_err(|err| Error::DeserializeFailed(err.to_string())),
            ConfigType::Dynamic(config) => prost::Message::decode(Bytes::from(config.value))
                .map_err(|err| {
                    Error::DeserializeFailed(format!(
                        "filter `{}`: config decode error: {}",
                        filter_name,
                        err.to_string()
                    ))
                })
                .and_then(|config| T::try_from(config).map_err(Error::ConvertProtoConfig)),
        }
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
    pub fn fixed(
        metrics_registry: Registry,
        config: Option<&serde_yaml::Value>,
    ) -> CreateFilterArgs {
        CreateFilterArgs {
            config: config.map(|config| ConfigType::Static(config)),
            metrics_registry,
        }
    }

    pub fn dynamic(
        metrics_registry: Registry,
        config: Option<prost_types::Any>,
    ) -> CreateFilterArgs<'static> {
        CreateFilterArgs {
            config: config.map(ConfigType::Dynamic),
            metrics_registry,
        }
    }

    pub fn with_metrics_registry(self, metrics_registry: Registry) -> Self {
        CreateFilterArgs {
            metrics_registry,
            ..self
        }
    }
}

/// FilterFactory provides the name and creation function for a given Filter.
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
        config.ok_or_else(|| Error::MissingConfig(self.name().into()))
    }
}

/// FilterRegistry is the registry of all Filters that can be applied in the system.
#[derive(Default)]
pub struct FilterRegistry {
    registry: HashMap<&'static str, Box<dyn FilterFactory>>,
}

impl FilterRegistry {
    /// insert adds a [`FilterFactory`] to this filter registry.
    pub fn insert<T: 'static>(&mut self, factory: T)
    where
        T: FilterFactory,
    {
        self.registry.insert(factory.name(), Box::new(factory));
    }

    /// insert_all adds the provided [`FilterFactory`]s to this filter registry.
    pub fn insert_all(&mut self, factories: Vec<Box<dyn FilterFactory>>) {
        for factory in factories {
            self.registry.insert(factory.name(), factory);
        }
    }

    /// get returns an instance of a filter for a given Key. Returns Error if not found,
    /// or if there is a configuration issue.
    pub fn get(&self, key: &str, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        match self.registry.get(key).map(|p| p.create_filter(args)) {
            None => Err(Error::NotFound(key.into())),
            Some(filter) => filter,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::test_utils::TestFilterFactory;

    use super::*;
    use crate::cluster::Endpoint;
    use crate::config::Endpoints;

    struct TestFilter {}

    impl Filter for TestFilter {
        fn read(&self, _: ReadContext) -> Option<ReadResponse> {
            None
        }

        fn write(&self, _: WriteContext) -> Option<WriteResponse> {
            None
        }
    }

    #[test]
    fn insert_and_get() {
        let mut reg = FilterRegistry::default();
        reg.insert(TestFilterFactory {});

        match reg.get(
            &String::from("not.found"),
            CreateFilterArgs::fixed(Registry::default(), None),
        ) {
            Ok(_) => unreachable!("should not be filter"),
            Err(err) => assert_eq!(Error::NotFound("not.found".to_string()), err),
        };

        assert!(reg
            .get(
                &String::from("TestFilter"),
                CreateFilterArgs::fixed(Registry::default(), None)
            )
            .is_ok());

        let filter = reg
            .get(
                &String::from("TestFilter"),
                CreateFilterArgs::fixed(Registry::default(), None),
            )
            .unwrap();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint = Endpoint::new(addr);

        assert!(filter
            .read(ReadContext::new(
                Endpoints::new(vec![Endpoint::new(
                    "127.0.0.1:8080".parse().unwrap(),
                )])
                .unwrap()
                .into(),
                addr,
                vec![]
            ))
            .is_some());
        assert!(filter
            .write(WriteContext::new(&endpoint, addr, addr, vec![],))
            .is_some());
    }
}
