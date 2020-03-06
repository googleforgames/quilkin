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
use std::sync::Arc;

use crate::config::EndPoint;
use std::net::SocketAddr;

/// Filter is a trait for routing and manipulating packets.
pub trait Filter: Send + Sync {
    /// local_filter filters packets from the local port, and potentially sends them
    /// to configured endpoints.
    /// This function should return the array of endpoints that the packet should be sent to,
    /// and the packet that should be sent (which may be manipulated) as well.
    /// If the packet should be rejected, return None.
    fn local_filter(
        &self,
        endpoints: &Vec<EndPoint>,
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)>;

    /// endpoint_filter filters packets received from an endpoint, that is going back to the
    /// original sender.
    /// This function should return the packet to be sent (which may be manipulated).
    /// If the packet should be rejected, return None.
    fn endpoint_filter(&self, endpoint: &EndPoint, contents: Vec<u8>) -> Option<Vec<u8>>;
}

/// FilterRegistry is the registry of all Filters that can be applied in the system.
pub struct FilterRegistry {
    // TODO: remove when used
    #[allow(dead_code)]
    registry: HashMap<String, Arc<dyn Filter>>,
}

impl FilterRegistry {
    pub fn new() -> FilterRegistry {
        FilterRegistry {
            registry: Default::default(),
        }
    }

    /// insert inserts a Filter into the registry.
    // TODO: remove when used
    #[allow(dead_code)]
    pub fn insert(&mut self, key: String, filter: impl Filter + 'static) {
        self.registry.insert(key, Arc::new(filter));
    }

    /// get returns the filter for a given Key. Returns None if not found.
    // TODO: remove when used
    #[allow(dead_code)]
    pub fn get(&self, key: &String) -> Option<&Arc<dyn Filter>> {
        self.registry.get(key)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    struct TestFilter {}
    impl Filter for TestFilter {
        fn local_filter(
            &self,
            _: &Vec<EndPoint>,
            _: SocketAddr,
            _: Vec<u8>,
        ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
            None
        }
        fn endpoint_filter(&self, _: &EndPoint, _: Vec<u8>) -> Option<Vec<u8>> {
            None
        }
    }

    #[test]
    fn insert_and_get() {
        let mut reg = FilterRegistry::new();
        reg.insert(String::from("test.filter"), TestFilter {});
        assert!(reg.get(&String::from("not.found")).is_none());
        assert!(reg.get(&String::from("test.filter")).is_some());

        let filter = reg.get(&String::from("test.filter")).unwrap();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint = EndPoint {
            name: "".to_string(),
            address: addr,
            connection_ids: vec![],
        };

        assert!(filter.local_filter(&vec![], addr, vec![]).is_none());
        assert!(filter.endpoint_filter(&endpoint, vec![]).is_none());
    }
}
