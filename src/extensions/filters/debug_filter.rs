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

use std::net::SocketAddr;

use slog::{info, o, Logger};

use crate::config::EndPoint;
use crate::extensions::filter_registry::{Error, FilterProvider};
use crate::extensions::Filter;
use serde_yaml::Value;

/// Debug Filter logs all incoming and outgoing packets
///
/// # Configuration
///
/// ```yaml
/// local:
///   port: 7000 # the port to receive traffic to locally
/// filters:
///   - name: quilkin.core.v1alpaha1.debug
///     config:
///       id: "debug-1"
/// client:
///   addresses:
///     - 127.0.0.1:7001
///   connection_id: 1x7ijy6
/// ```
///  `config.id` (optional) adds a "id" field with a given value to each log line.
///     This can be useful to identify debug log positioning within a filter config if you have
///     multiple DebugFilters configured.
///
pub struct DebugFilter {
    log: Logger,
}

impl DebugFilter {
    /// Constructor for the DebugFilter. Pass in a "id" to append a string to your log messages from this
    /// Filter.
    fn new(base: &Logger, id: Option<String>) -> Self {
        let log = match id {
            None => base.new(o!("source" => "extensions::DebugFilter")),
            Some(id) => base.new(o!("source" => "extensions::DebugFilter", "id" => id)),
        };

        DebugFilter { log }
    }
}

/// Provider for the DebugFilter
pub struct DebugFilterProvider {}
impl FilterProvider for DebugFilterProvider {
    fn name(&self) -> String {
        return String::from("quilkin.core.v1alpaha1.debug");
    }

    fn from_config(&self, logger: &Logger, config: &Value) -> Result<Box<dyn Filter>, Error> {
        let prefix = match config {
            serde_yaml::Value::Mapping(map) => match map.get(&serde_yaml::Value::from("id")) {
                Some(value) => match value.as_str() {
                    Some(str) => Some(str.to_string()),
                    None => {
                        return Err(Error::FieldInvalid {
                            field: "config.id".to_string(),
                            reason: "id value should be a string".to_string(),
                        });
                    }
                },
                None => None,
            },
            _ => None,
        };

        Ok(Box::new(DebugFilter::new(logger, prefix)))
    }
}

impl Filter for DebugFilter {
    fn local_receive_filter(
        &self,
        endpoints: &Vec<EndPoint>,
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
        info!(self.log, "received local packet"; "from" => from, "contents" => packet_to_string(contents.clone()));
        Some((endpoints.to_vec(), contents))
    }

    fn local_send_filter(&self, to: SocketAddr, contents: Vec<u8>) -> Option<Vec<u8>> {
        info!(self.log, "sending local packet"; "to" => to, "contents" => packet_to_string(contents.clone()));
        Some(contents)
    }

    fn endpoint_receive_filter(
        &self,
        endpoint: &EndPoint,
        recv_addr: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        info!(self.log, "received endpoint packet"; "endpoint" => endpoint.name.clone(),
        "recv_addr" => recv_addr, 
        "contents" => packet_to_string(contents.clone()));
        Some(contents)
    }

    fn endpoint_send_filter(
        &self,
        endpoint: &EndPoint,
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        info!(self.log, "sending endpoint packet"; "endpoint" => endpoint.name.clone(),
         "from" => from, "contents" => packet_to_string(contents.clone()));
        Some(contents)
    }
}

/// packet_to_string takes the content, and attempts to convert it to a string.
/// Returns a string of "error decoding packet" on failure.
fn packet_to_string(contents: Vec<u8>) -> String {
    match String::from_utf8(contents) {
        Ok(str) => str,
        Err(_) => String::from("error decoding packet"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::test_utils::logger;

    use super::*;
    use serde_yaml::Mapping;
    use serde_yaml::Value;

    #[test]
    fn local_receive_filter() {
        let df = DebugFilter::new(&logger(), None);
        let endpoints = vec![EndPoint {
            name: "e1".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357),
            connection_ids: vec![],
        }];
        let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12358);
        let contents = "hello".to_string().into_bytes();

        match df.local_receive_filter(&endpoints, from, contents.clone()) {
            None => assert!(false, "should return a result"),
            Some((result_endpoints, result_contents)) => {
                assert_eq!(endpoints, result_endpoints);
                assert_eq!(contents, result_contents);
            }
        }
    }

    #[test]
    fn local_send_filter() {
        let df = DebugFilter::new(&logger(), None);
        let to = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12358);
        let contents = "hello".to_string().into_bytes();

        match df.local_send_filter(to, contents.clone()) {
            None => assert!(false, "should return a result"),
            Some(result_contents) => assert_eq!(contents, result_contents),
        }
    }

    #[test]
    fn endpoint_receive_filter() {
        let df = DebugFilter::new(&logger(), None);
        let endpoint = EndPoint {
            name: "e1".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357),
            connection_ids: vec![],
        };
        let contents = "hello".to_string().into_bytes();

        match df.endpoint_receive_filter(&endpoint, endpoint.address, contents.clone()) {
            None => assert!(false, "should return a result"),
            Some(result_contents) => assert_eq!(contents, result_contents),
        }
    }

    #[test]
    fn endpoint_send_filter() {
        let df = DebugFilter::new(&logger(), None);
        let endpoint = EndPoint {
            name: "e1".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12357),
            connection_ids: vec![],
        };
        let contents = "hello".to_string().into_bytes();
        let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 12358);

        match df.endpoint_send_filter(&endpoint, from, contents.clone()) {
            None => assert!(false, "should return a result"),
            Some(result_contents) => assert_eq!(contents, result_contents),
        }
    }

    #[test]
    fn from_config_with_id() {
        let log = logger();
        let mut map = Mapping::new();
        let provider = DebugFilterProvider {};

        map.insert(Value::from("id"), Value::from("name"));
        assert!(provider.from_config(&log, &Value::Mapping(map)).is_ok());
    }

    #[test]
    fn from_config_without_id() {
        let log = logger();
        let mut map = Mapping::new();
        let provider = DebugFilterProvider {};

        map.insert(Value::from("id"), Value::from("name"));
        assert!(provider.from_config(&log, &Value::Mapping(map)).is_ok());
    }

    #[test]
    fn from_config_should_panic() {
        let log = logger();
        let mut map = Mapping::new();
        let provider = DebugFilterProvider {};

        map.insert(Value::from("id"), Value::from(false));
        match provider.from_config(&log, &Value::Mapping(map)) {
            Ok(_) => assert!(false, "should be an error"),
            Err(err) => {
                assert_eq!(
                    Error::FieldInvalid {
                        field: "config.id".to_string(),
                        reason: "id value should be a string".to_string()
                    }
                    .to_string(),
                    err.to_string()
                );
            }
        }
    }
}
