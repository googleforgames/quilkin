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
use slog::Logger;
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

pub type BoxFilter = Box<dyn Filter>;
/// Function that returns a filter
type FnFilter = Box<dyn Fn(&Logger, &serde_yaml::Value) -> BoxFilter + Send>;

/// FilterRegistry is the registry of all Filters that can be applied in the system.
pub struct FilterRegistry {
    log: Logger,
    registry: HashMap<String, FnFilter>,
}

impl FilterRegistry {
    pub fn new(base: &Logger) -> FilterRegistry {
        FilterRegistry {
            log: base.clone(),
            registry: Default::default(),
        }
    }

    /// insert inserts the fucntion that will create a Filter into the registry.
    pub fn insert(&mut self, key: String, filter: FnFilter) {
        self.registry.insert(key, filter);
    }

    /// get returns an instance of a filter for a given Key. Returns None if not found.
    pub fn get(&self, key: &String, config: &serde_yaml::Value) -> Option<Box<dyn Filter>> {
        self.registry.get(key).map(|f| f(&self.log, &config))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::test_utils::logger;

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
        reg.insert(
            String::from("test.filter"),
            Box::new(|_, _| Box::new(TestFilter {})),
        );
        let config = serde_yaml::Value::Null;
        assert!(reg.get(&String::from("not.found"), &config).is_none());
        assert!(reg.get(&String::from("test.filter"), &config).is_some());

        let filter = reg.get(&String::from("test.filter"), &config).unwrap();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let endpoint = EndPoint {
            name: "".to_string(),
            address: addr,
            connection_ids: vec![],
        };

        assert!(filter.local_receive_filter(&vec![], addr, vec![]).is_none());
        assert!(filter
            .endpoint_receive_filter(&endpoint, addr, vec![])
            .is_none());
    }
}
