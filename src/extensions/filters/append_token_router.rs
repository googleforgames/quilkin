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

use slog::{debug, o, warn, Logger};

use crate::config::{ConnectionConfig, ConnectionId, EndPoint};
use crate::extensions::filter_registry::Error::{FieldInvalid, FieldNotFound};
use crate::extensions::{CreateFilterArgs, Error, Filter, FilterFactory};

pub struct AppendTokenRouterFactory {
    log: Logger,
}

impl AppendTokenRouterFactory {
    pub fn new(base: &Logger) -> Self {
        AppendTokenRouterFactory { log: base.clone() }
    }
}

impl FilterFactory for AppendTokenRouterFactory {
    fn name(&self) -> String {
        String::from("quilkin.extensions.filters.append_token_router.v1alpha1.AppendTokenRouter")
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let filter: Box<dyn Filter> = match args.connection {
            ConnectionConfig::Client { connection_id, .. } => {
                Box::new(Client::new(&self.log, connection_id.clone()))
            }
            ConnectionConfig::Server { .. } => {
                let result = args
                    .config
                    .ok_or_else(|| FieldNotFound("config".into()))?
                    .get("connection_id_bytes")
                    .ok_or_else(|| FieldNotFound("config.connection_id_bytes".into()))?;
                let cil = result.as_u64().ok_or(FieldInvalid {
                    field: "config.connection_id_bytes".into(),
                    reason: "should be an unsigned integer".into(),
                })?;

                Box::new(Server::new(&self.log, cil as usize))
            }
        };
        Ok(Box::new(AppendTokenRouter::new(filter)))
    }
}

///
/// Append Token Router is a Client/Server filter pair that appends the Client
/// client.connection_id to each packet, and then when received on the Server
/// side, it is stripped off the packet, and compared to endpoints and on match
/// the packet is sent on to that endpoint.
///
pub struct AppendTokenRouter {
    filter: Box<dyn Filter>,
}

impl AppendTokenRouter {
    pub fn new(filter: Box<dyn Filter>) -> Self {
        AppendTokenRouter {
            // either the Server or Client filter
            filter,
        }
    }
}

impl Filter for AppendTokenRouter {
    fn on_downstream_receive(
        &self,
        endpoints: &[EndPoint],
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
        self.filter.on_downstream_receive(endpoints, from, contents)
    }

    fn on_upstream_receive(
        &self,
        endpoint: &EndPoint,
        from: SocketAddr,
        to: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        self.filter
            .on_upstream_receive(endpoint, from, to, contents)
    }
}

struct Client {
    log: Logger,
    connection_id: ConnectionId,
}

impl Client {
    pub fn new(base: &Logger, connection_id: ConnectionId) -> Self {
        Client {
            log: base.new(o!("source" => "extensions::AppendTokenRouter::Client")),
            connection_id,
        }
    }
}

impl Filter for Client {
    fn on_downstream_receive(
        &self,
        endpoints: &[EndPoint],
        _: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
        let mut contents = contents;
        let mut token = self.connection_id.as_ref().clone();
        contents.append(&mut token);

        debug!(self.log, "on_downstream_receive"; "contents" => String::from_utf8(contents.clone()).unwrap_or(format!("{:?}", contents)));
        Some((endpoints.to_vec(), contents))
    }

    fn on_upstream_receive(
        &self,
        _: &EndPoint,
        _: SocketAddr,
        _: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        Some(contents)
    }
}

struct Server {
    log: Logger,
    // number of bytes the connection id is
    connection_id_length: usize,
}

impl Server {
    pub fn new(base: &Logger, connection_id_length: usize) -> Self {
        Server {
            log: base.new(o!("source" => "extensions::AppendTokenRouter::Server")),
            connection_id_length,
        }
    }
}

impl Filter for Server {
    fn on_downstream_receive(
        &self,
        endpoints: &[EndPoint],
        _: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
        // splits the connection_id off the content and returns the value
        if self.connection_id_length > contents.len() {
            warn!(self.log, "connection_id_length was larger than packet size. Packet dropped.";
                "connection_id_length" => self.connection_id_length, "packet_length" => contents.len());
            return None;
        }
        let mut contents = contents;
        let connection_id =
            ConnectionId::from(contents.split_off(contents.len() - self.connection_id_length));

        let filtered_endpoints: Vec<EndPoint> = endpoints
            .iter()
            .filter(|endpoint| {
                endpoint
                    .connection_ids
                    .iter()
                    .any(|id| *id == connection_id)
            })
            .cloned()
            .collect();

        debug!(self.log, "on_downstream_receive";
        "filtered_endpoints" => filtered_endpoints.clone().into_iter().map(|e| e.name).collect::<Vec<String>>().as_slice().join(", "),
        "contents" => String::from_utf8(contents.clone()).unwrap_or(format!("{:?}", contents)),
        "connection_id" => String::from_utf8(connection_id.as_ref().clone()).unwrap_or(format!("{:?}", connection_id)));

        if filtered_endpoints.is_empty() {
            return None;
        }

        Some((filtered_endpoints, contents.to_vec()))
    }

    fn on_upstream_receive(
        &self,
        _: &EndPoint,
        _: SocketAddr,
        _: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        Some(contents)
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::{Mapping, Number, Value};

    use crate::test_utils::{assert_filter_on_upstream_receive_no_change, logger};

    use super::*;

    #[test]
    fn factory_server() {
        let log = logger();
        let factory = AppendTokenRouterFactory::new(&log);
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let yaml = "connection_id_bytes: 3";
        let value: Value = serde_yaml::from_str(yaml).unwrap();
        let config = Some(&value);

        let filter = factory
            .create_filter(CreateFilterArgs::new(&connection, config))
            .unwrap();

        assert_filter_on_upstream_receive_no_change(&filter);
        assert_server_on_downstream_receive(&filter);
    }

    #[test]
    fn factory_client() {
        let log = logger();
        let factory = AppendTokenRouterFactory::new(&log);
        let connection = ConnectionConfig::Client {
            addresses: vec![],
            connection_id: "abc".into(),
            lb_policy: None,
        };

        let filter = factory
            .create_filter(CreateFilterArgs::new(&connection, None))
            .unwrap();
        assert_filter_on_upstream_receive_no_change(&filter);
        assert_client_on_downstream_receive(&filter);
    }

    #[test]
    fn client_on_downstream_receive() {
        let log = logger();
        let connection_id: ConnectionId = "abc".into();
        let client = Client::new(&log, connection_id);
        assert_client_on_downstream_receive(&client);
    }

    #[test]
    fn client_on_upstream_receive() {
        let log = logger();
        let connection_id: ConnectionId = "abc".into();
        let client = Client::new(&log, connection_id);
        assert_filter_on_upstream_receive_no_change(&client);
    }

    #[test]
    fn server_on_downstream_receive() {
        let log = logger();
        let server = Server::new(&log, 3);
        assert_server_on_downstream_receive(&server)
    }

    #[test]
    fn server_on_downstream_receive_bad_connection_id_length() {
        let log = logger();
        let server = Server::new(&log, 99);
        let e1 = EndPoint::new(
            "e1".into(),
            "127.0.0.1:80".parse().unwrap(),
            vec!["abc".into()],
        );

        assert!(server
            .on_downstream_receive(
                vec![e1].as_slice(),
                "127.0.0.1:70".parse().unwrap(),
                "helloabc".as_bytes().to_vec(),
            )
            .is_none());
    }

    #[test]
    fn server_on_downstream_receive_no_endpoints() {
        let log = logger();
        let server = Server::new(&log, 3);
        let e1 = EndPoint::new(
            "e1".into(),
            "127.0.0.1:80".parse().unwrap(),
            vec!["xyz".into()],
        );

        assert!(server
            .on_downstream_receive(
                vec![e1].as_slice(),
                "127.0.0.1:70".parse().unwrap(),
                "helloabc".as_bytes().to_vec(),
            )
            .is_none());
    }

    #[test]
    fn server_on_upstream_receive() {
        let log = logger();
        let server = Server::new(&log, 3);
        assert_filter_on_upstream_receive_no_change(&server);
    }

    #[test]
    fn create_from_config_server_empty_config() {
        let log = logger();
        let map = Mapping::new();
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let factory = AppendTokenRouterFactory::new(&log);

        match factory.create_filter(CreateFilterArgs::new(
            &connection,
            Some(&Value::Mapping(map)),
        )) {
            Ok(_) => assert!(false, "should fail validation"),
            Err(err) => assert_eq!(FieldNotFound("config.connection_id_bytes".into()), err),
        };
    }

    #[test]
    fn create_from_config_valid_connection_id() {
        let log = logger();
        let mut map = Mapping::new();
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let factory = AppendTokenRouterFactory::new(&log);
        map.insert("connection_id_bytes".into(), Value::Number(Number::from(7)));

        assert!(
            factory
                .create_filter(CreateFilterArgs::new(
                    &connection,
                    Some(&Value::Mapping(map))
                ))
                .is_ok(),
            "should be a valid config"
        );
    }

    #[test]
    fn create_from_config_invalid_connection_id() {
        let log = logger();
        let mut map = Mapping::new();
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let factory = AppendTokenRouterFactory::new(&log);
        map.insert("connection_id_bytes".into(), Value::String("stuff".into()));

        match factory.create_filter(CreateFilterArgs::new(
            &connection,
            Some(&Value::Mapping(map)),
        )) {
            Ok(_) => assert!(false, "should fail validation"),
            Err(err) => assert_eq!(
                FieldInvalid {
                    field: "config.connection_id_bytes".into(),
                    reason: "should be an unsigned integer".into(),
                },
                err
            ),
        };
    }

    /// assert that on_downstream_receive does the right thing
    /// for a server configuration.
    /// Assumes that the connection token is "abc"
    fn assert_client_on_downstream_receive<F>(filter: &F)
    where
        F: Filter,
    {
        let contents = "hello".to_string().into_bytes();
        let endpoints = vec![EndPoint {
            name: "e1".to_string(),
            address: "127.0.0.1:81".parse().unwrap(),
            connection_ids: vec![],
        }];

        match filter.on_downstream_receive(
            endpoints.as_slice(),
            "127.0.0.1:80".parse().unwrap(),
            contents,
        ) {
            None => assert!(false, "should get a result"),
            Some((result_endpoints, result_content)) => {
                assert_eq!(endpoints, result_endpoints);
                assert_eq!("helloabc".to_string().into_bytes(), result_content);
            }
        }
    }

    /// assert that on_downstream_receive does the right thing
    /// for a server configuration.
    /// Assumes that the connection string length is 3
    fn assert_server_on_downstream_receive<F>(filter: &F)
    where
        F: Filter,
    {
        let e1 = EndPoint::new(
            "e1".into(),
            "127.0.0.1:80".parse().unwrap(),
            vec!["abc".into()],
        );
        let e2 = EndPoint::new("e2".into(), "127.0.0.1:90".parse().unwrap(), vec![]);

        match filter.on_downstream_receive(
            vec![e1.clone(), e2].as_slice(),
            "127.0.0.1:70".parse().unwrap(),
            "helloabc".as_bytes().to_vec(),
        ) {
            None => assert!(false, "should be a result"),
            Some((endpoints, content)) => {
                assert_eq!(1, endpoints.len());
                assert_eq!(endpoints[0], e1);
                assert_eq!("hello".as_bytes().to_vec(), content);
            }
        }
    }
}
