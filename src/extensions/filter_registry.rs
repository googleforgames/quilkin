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

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

use serde::export::Formatter;

use crate::config::EndPoint;

/// Filter is a trait for routing and manipulating packets.
pub trait Filter: Send + Sync {
    /// on_downstream_receive filters packets received from the local port, and potentially sends them
    /// to configured endpoints.
    /// This function should return the array of endpoints that the packet should be sent to,
    /// and the packet that should be sent (which may be manipulated) as well.
    /// If the packet should be rejected, return None.
    fn on_downstream_receive(
        &self,
        endpoints: &[EndPoint],
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)>;

    /// on_upstream_receive filters packets received from `from`, to a given endpoint,
    /// that are going back to the original sender.
    /// This function should return the packet to be sent (which may be manipulated).
    /// If the packet should be rejected, return None.
    fn on_upstream_receive(
        &self,
        endpoint: &EndPoint,
        from: SocketAddr,
        to: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>>;
}

#[derive(Debug, PartialEq)]
/// Error is an error when attempting to create a Filter from_config() from a FilterFactory
pub enum Error {
    NotFound(String),
    FieldInvalid { field: String, reason: String },
    DeserializeFailed(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound(key) => write!(f, "filter {} is not found", key),
            Error::FieldInvalid { field, reason } => {
                write!(f, "field {} is invalid: {}", field, reason)
            }
            Error::DeserializeFailed(reason) => write!(f, "Deserialization failed: {}", reason),
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
    ///     `quilkin.extensions.filters.debug_filter.v1alpha1.DebugFilter`
    fn name(&self) -> String;
    fn create_from_config(&self, config: &serde_yaml::Value) -> Result<Box<dyn Filter>, Error>;
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
    pub fn get(&self, key: &str, config: &serde_yaml::Value) -> Result<Box<dyn Filter>, Error> {
        match self
            .registry
            .get(key)
            .map(|p| p.create_from_config(&config))
        {
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

    struct TestFilter {}

    impl Filter for TestFilter {
        fn on_downstream_receive(
            &self,
            _: &[EndPoint],
            _: SocketAddr,
            _: Vec<u8>,
        ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
            None
        }

        fn on_upstream_receive(
            &self,
            _: &EndPoint,
            _: SocketAddr,
            _: SocketAddr,
            _: Vec<u8>,
        ) -> Option<Vec<u8>> {
            None
        }
    }

    #[test]
    fn insert_and_get() {
        let mut reg = FilterRegistry::default();
        reg.insert(TestFilterFactory {});
        let config = serde_yaml::Value::Null;

        match reg.get(&String::from("not.found"), &config) {
            Ok(_) => assert!(false, "should not be filter"),
            Err(err) => assert_eq!(Error::NotFound("not.found".to_string()), err),
        };

        assert!(reg.get(&String::from("TestFilter"), &config).is_ok());

        let filter = reg.get(&String::from("TestFilter"), &config).unwrap();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint = EndPoint {
            name: "".to_string(),
            address: addr,
            connection_ids: vec![],
        };

        assert!(filter
            .on_downstream_receive(&vec![], addr, vec![])
            .is_some());
        assert!(filter
            .on_upstream_receive(&endpoint, addr, addr, vec![])
            .is_some());
    }
}
