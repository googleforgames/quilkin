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

use crate::config::EndPoint;
use serde::export::Formatter;
use slog::Logger;
use std::fmt;
use std::net::SocketAddr;

/// Filter is a trait for routing and manipulating packets.
pub trait Filter: Send + Sync {
    /// local_receive_filter filters packets received from the local port, and potentially sends them
    /// to configured endpoints.
    /// This function should return the array of endpoints that the packet should be sent to,
    /// and the packet that should be sent (which may be manipulated) as well.
    /// If the packet should be rejected, return None.
    fn local_receive_filter(
        &self,
        endpoints: &Vec<EndPoint>,
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)>;

    /// local_send_filter intercepts packets that are being sent back to the original local port sender
    /// This function should return the packet to be sent (which may be manipulated).
    /// If the packet should be rejected, return None.
    fn local_send_filter(&self, to: SocketAddr, contents: Vec<u8>) -> Option<Vec<u8>>;

    /// endpoint_receive_filter filters packets received from recv_addr, but expected from the given endpoint,
    /// that are going back to the original sender.
    /// This function should return the packet to be sent (which may be manipulated).
    /// If the packet should be rejected, return None.
    fn endpoint_receive_filter(
        &self,
        endpoint: &EndPoint,
        recv_addr: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>>;

    /// endpoint_send_filter intercepts packets that are being sent back to the original
    /// endpoint sender address
    /// This function should return the packet to be sent (which may be manipulated).
    /// If the packet should be rejected, return None.
    fn endpoint_send_filter(
        &self,
        endpoint: &EndPoint,
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>>;
}

#[derive(Debug, PartialEq)]
/// ConfigError is an error when attempting to create a Filter from_config() from a FilterProvider
pub enum Error {
    NotFound(String),
    FieldInvalid { field: String, reason: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound(key) => write!(f, "filter {} is not found", key),
            Error::FieldInvalid { field, reason } => {
                write!(f, "field {} is invalid: {}", field, reason)
            }
        }
    }
}

/// FilterProvider provides the name and creation function for a given Filter.
pub trait FilterProvider: Sync + Send {
    /// name returns the configuration name for the Filter
    fn name(&self) -> String;
    fn from_config(
        &self,
        logger: &Logger,
        config: &serde_yaml::Value,
    ) -> Result<Box<dyn Filter>, Error>;
}

/// FilterRegistry is the registry of all Filters that can be applied in the system.
pub struct FilterRegistry {
    log: Logger,
    registry: HashMap<String, Box<dyn FilterProvider>>,
}

impl FilterRegistry {
    pub fn new(base: &Logger) -> FilterRegistry {
        FilterRegistry {
            log: base.clone(),
            registry: Default::default(),
        }
    }

    /// insert registers a Filter under the provider's given name.
    pub fn insert<P: 'static>(&mut self, provider: P)
    where
        P: FilterProvider,
    {
        self.registry.insert(provider.name(), Box::new(provider));
    }

    /// get returns an instance of a filter for a given Key. Returns None if not found.
    pub fn get(&self, key: &String, config: &serde_yaml::Value) -> Result<Box<dyn Filter>, Error> {
        match self
            .registry
            .get(key)
            .map(|p| p.from_config(&self.log, &config))
        {
            None => Err(Error::NotFound(key.clone())),
            Some(filter) => filter,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::test_utils::{logger, TestFilterProvider};

    struct TestFilter {}

    impl Filter for TestFilter {
        fn local_receive_filter(
            &self,
            _: &Vec<EndPoint>,
            _: SocketAddr,
            _: Vec<u8>,
        ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
            None
        }

        fn local_send_filter(&self, _: SocketAddr, _: Vec<u8>) -> Option<Vec<u8>> {
            None
        }

        fn endpoint_receive_filter(
            &self,
            _: &EndPoint,
            _: SocketAddr,
            _: Vec<u8>,
        ) -> Option<Vec<u8>> {
            None
        }

        fn endpoint_send_filter(&self, _: &EndPoint, _: SocketAddr, _: Vec<u8>) -> Option<Vec<u8>> {
            None
        }
    }

    #[test]
    fn insert_and_get() {
        let logger = logger();
        let mut reg = FilterRegistry::new(&logger);
        reg.insert(TestFilterProvider {});
        let config = serde_yaml::Value::Null;

        // TOXO: might want to convert to equals operation
        assert!(reg.get(&String::from("not.found"), &config).is_err());
        assert!(reg.get(&String::from("TestFilter"), &config).is_ok());

        let filter = reg.get(&String::from("TestFilter"), &config).unwrap();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint = EndPoint {
            name: "".to_string(),
            address: addr,
            connection_ids: vec![],
        };

        assert!(filter.local_receive_filter(&vec![], addr, vec![]).is_some());
        assert!(filter
            .endpoint_receive_filter(&endpoint, addr, vec![])
            .is_some());
    }
}
