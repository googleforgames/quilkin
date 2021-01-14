/*
 * Copyright 2020 Google LLC All Rights Reserved.
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
use std::fmt;
use std::marker::PhantomData;
use std::net::SocketAddr;

use prometheus::{Error as MetricsError, Registry};

use crate::cluster::Endpoint;
use crate::config::{UpstreamEndpoints, ValidationError};

/// Contains the input arguments to [on_downstream_receive](crate::extensions::filter_registry::Filter::on_downstream_receive)
pub struct DownstreamContext {
    /// The upstream endpoints that the packet will be forwarded to.
    pub endpoints: UpstreamEndpoints,
    /// The source of the received packet.
    pub from: SocketAddr,
    /// Contents of the received packet.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another
    pub metadata: HashMap<String, Box<dyn Any + Send>>,
    // Enforce using constructor to create this struct.
    phantom: PhantomData<()>,
}

/// Contains the output of [on_downstream_receive](crate::extensions::filter_registry::Filter::on_downstream_receive)
///
/// New instances are created from a [`DownstreamContext`]
///
/// ```rust
/// # use quilkin::extensions::{DownstreamContext, DownstreamResponse};
///   fn on_downstream_receive(ctx: DownstreamContext) -> Option<DownstreamResponse> {
///       Some(ctx.into())
///   }
/// ```
pub struct DownstreamResponse {
    /// The upstream endpoints that the packet should be forwarded to.
    pub endpoints: UpstreamEndpoints,
    /// Contents of the packet to be forwarded.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another
    pub metadata: HashMap<String, Box<dyn Any + Send>>,
    // Enforce using constructor to create this struct.
    phantom: PhantomData<()>,
}

/// Contains the input arguments to [on_upstream_receive](crate::extensions::filter_registry::Filter::on_upstream_receive)
pub struct UpstreamContext<'a> {
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

/// Contains the output of [on_upstream_receive](crate::extensions::filter_registry::Filter::on_upstream_receive)
///
/// New instances are created from an [`UpstreamContext`]
///
/// ```rust
/// # use quilkin::extensions::{UpstreamContext, UpstreamResponse};
///   fn on_upstream_receive(ctx: UpstreamContext) -> Option<UpstreamResponse> {
///       Some(ctx.into())
///   }
/// ```
pub struct UpstreamResponse {
    /// Contents of the packet to be sent back to the original sender.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another
    pub metadata: HashMap<String, Box<dyn Any + Send>>,
    // Enforce using constructor to create this struct.
    phantom: PhantomData<()>,
}

impl DownstreamContext {
    /// Creates a new [`DownstreamContext`]
    pub fn new(endpoints: UpstreamEndpoints, from: SocketAddr, contents: Vec<u8>) -> Self {
        Self {
            endpoints,
            from,
            contents,
            metadata: HashMap::new(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`DownstreamContext`] from a [`DownstreamResponse`]
    pub fn with_response(from: SocketAddr, response: DownstreamResponse) -> Self {
        Self {
            endpoints: response.endpoints,
            from,
            contents: response.contents,
            metadata: response.metadata,
            phantom: PhantomData,
        }
    }
}

impl From<DownstreamContext> for DownstreamResponse {
    fn from(ctx: DownstreamContext) -> Self {
        Self {
            endpoints: ctx.endpoints,
            contents: ctx.contents,
            metadata: ctx.metadata,
            phantom: ctx.phantom,
        }
    }
}

impl UpstreamContext<'_> {
    /// Creates a new [`UpstreamContext`]
    pub fn new(
        endpoint: &Endpoint,
        from: SocketAddr,
        to: SocketAddr,
        contents: Vec<u8>,
    ) -> UpstreamContext {
        UpstreamContext {
            endpoint,
            from,
            to,
            contents,
            metadata: HashMap::new(),
            phantom: PhantomData,
        }
    }

    /// Creates a new [`UpstreamContext`] from a [`UpstreamResponse`]
    pub fn with_response(
        endpoint: &Endpoint,
        from: SocketAddr,
        to: SocketAddr,
        response: UpstreamResponse,
    ) -> UpstreamContext {
        UpstreamContext {
            endpoint,
            from,
            to,
            contents: response.contents,
            metadata: response.metadata,
            phantom: PhantomData,
        }
    }
}

impl From<UpstreamContext<'_>> for UpstreamResponse {
    fn from(ctx: UpstreamContext) -> Self {
        Self {
            contents: ctx.contents,
            phantom: ctx.phantom,
            metadata: ctx.metadata,
        }
    }
}

/// Filter is a trait for routing and manipulating packets.
pub trait Filter: Send + Sync {
    /// on_downstream_receive filters packets received from the local port, and potentially sends them
    /// to configured endpoints.
    /// This function should return a [`DownstreamResponse`] containing the array of
    /// endpoints that the packet should be sent to and the packet that should be
    /// sent (which may be manipulated) as well.
    /// If the packet should be rejected, return None.
    /// By default, passes the context through unchanged
    fn on_downstream_receive(&self, ctx: DownstreamContext) -> Option<DownstreamResponse> {
        Some(ctx.into())
    }

    /// on_upstream_receive filters packets received upstream and destined
    /// for a given endpoint, that are going back to the original sender.
    /// This function should return an [`UpstreamResponse`] containing the packet to
    /// be sent (which may be manipulated).
    /// If the packet should be rejected, return None.
    /// By default, passes the context through unchanged
    fn on_upstream_receive(&self, ctx: UpstreamContext) -> Option<UpstreamResponse> {
        Some(ctx.into())
    }
}

#[derive(Debug, PartialEq)]
/// Error is an error when attempting to create a Filter from_config() from a FilterFactory
pub enum Error {
    NotFound(String),
    FieldInvalid { field: String, reason: String },
    DeserializeFailed(String),
    InitializeMetricsFailed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound(key) => write!(f, "filter {} is not found", key),
            Error::FieldInvalid { field, reason } => {
                write!(f, "field {} is invalid: {}", field, reason)
            }
            Error::DeserializeFailed(reason) => write!(f, "Deserialization failed: {}", reason),
            Error::InitializeMetricsFailed(reason) => {
                write!(f, "failed to initialize metrics: {}", reason)
            }
        }
    }
}

impl Into<ValidationError> for Error {
    fn into(self) -> ValidationError {
        ValidationError::FilterInvalid(self)
    }
}

impl From<MetricsError> for Error {
    fn from(error: MetricsError) -> Self {
        Error::InitializeMetricsFailed(error.to_string())
    }
}

/// Arguments needed to create a new filter.
pub struct CreateFilterArgs<'a> {
    /// Configuration for the filter.
    pub config: Option<&'a serde_yaml::Value>,
    /// metrics_registry is used to register filter metrics collectors.
    pub metrics_registry: Registry,
}

impl CreateFilterArgs<'_> {
    pub fn new(config: Option<&serde_yaml::Value>) -> CreateFilterArgs {
        CreateFilterArgs {
            config,
            metrics_registry: Registry::default(),
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
    fn name(&self) -> String;

    /// Returns a filter based on the provided arguments.
    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error>;
}

/// FilterRegistry is the registry of all Filters that can be applied in the system.
#[derive(Default)]
pub struct FilterRegistry {
    registry: HashMap<String, Box<dyn FilterFactory>>,
}

impl FilterRegistry {
    /// insert registers a Filter under the provider's given name.
    pub fn insert<P: 'static>(&mut self, provider: P)
    where
        P: FilterFactory,
    {
        self.registry.insert(provider.name(), Box::new(provider));
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
        fn on_downstream_receive(&self, _: DownstreamContext) -> Option<DownstreamResponse> {
            None
        }

        fn on_upstream_receive(&self, _: UpstreamContext) -> Option<UpstreamResponse> {
            None
        }
    }

    #[test]
    fn insert_and_get() {
        let mut reg = FilterRegistry::default();
        reg.insert(TestFilterFactory {});

        match reg.get(&String::from("not.found"), CreateFilterArgs::new(None)) {
            Ok(_) => unreachable!("should not be filter"),
            Err(err) => assert_eq!(Error::NotFound("not.found".to_string()), err),
        };

        assert!(reg
            .get(&String::from("TestFilter"), CreateFilterArgs::new(None))
            .is_ok());

        let filter = reg
            .get(&String::from("TestFilter"), CreateFilterArgs::new(None))
            .unwrap();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint = Endpoint::from_address(addr);

        assert!(filter
            .on_downstream_receive(DownstreamContext::new(
                Endpoints::new(vec![Endpoint::from_address(
                    "127.0.0.1:8080".parse().unwrap(),
                )])
                .unwrap()
                .into(),
                addr,
                vec![]
            ))
            .is_some());
        assert!(filter
            .on_upstream_receive(UpstreamContext::new(&endpoint, addr, addr, vec![],))
            .is_some());
    }
}
