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

extern crate quilkin;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use serde_yaml::{Mapping, Value};
    use slog::info;

    use quilkin::config::{Config, ConnectionConfig, EndPoint, Filter, Local};
    use quilkin::extensions::filters::DebugFilterFactory;
    use quilkin::extensions::{default_registry, FilterFactory};
    use quilkin::test_utils::{
        echo_server, logger, recv_multiple_packets, run_proxy, TestFilterFactory,
    };

    #[tokio::test]
    async fn test_filter() {
        let base_logger = logger();

        // create two echo servers as endpoints
        let echo = echo_server().await;

        // create server configuration
        let server_port = 12346;
        let server_config = Config {
            local: Local { port: server_port },
            filters: vec![Filter {
                name: "TestFilter".to_string(),
                config: None,
            }],
            connections: ConnectionConfig::Server {
                endpoints: vec![EndPoint {
                    name: "server".to_string(),
                    address: echo,
                    connection_ids: vec![],
                }],
            },
        };
        assert_eq!(Ok(()), server_config.validate());

        let mut registry = default_registry(&base_logger);
        registry.insert(TestFilterFactory {});
        let close_server = run_proxy(registry, server_config);

        // create a local client
        let client_port = 12347;
        let client_config = Config {
            local: Local { port: client_port },
            filters: vec![Filter {
                name: "TestFilter".to_string(),
                config: None,
            }],
            connections: ConnectionConfig::Client {
                addresses: vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    server_port,
                )],
                connection_id: "".into(),
                lb_policy: None,
            },
        };
        assert_eq!(Ok(()), client_config.validate());

        let mut registry = default_registry(&base_logger);
        registry.insert(TestFilterFactory {});
        let close_client = run_proxy(registry, client_config);

        // let's send the packet
        let (mut recv_chan, mut send) = recv_multiple_packets(&base_logger).await;

        // game_client
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
        info!(base_logger, "Sending hello"; "addr" => local_addr);
        send.send_to("hello".as_bytes(), &local_addr).await.unwrap();

        let result = recv_chan.recv().await.unwrap();
        // since we don't know the ephemeral ip addresses in use, we'll search for
        // substrings for the results we expect that the TestFilter will inject in
        // the round-tripped packets.
        assert_eq!(
            2,
            result.matches("odr").count(),
            "Should be 2 on_downstream_receive calls in {}",
            result
        );
        assert_eq!(
            2,
            result.matches("our").count(),
            "Should be 2 on_upstream_receive calls in {}",
            result
        );

        close_server();
        close_client();
    }

    #[tokio::test]
    async fn debug_filter() {
        let base_logger = logger();
        // handy for grabbing the configuration name
        let factory = DebugFilterFactory::new(&base_logger);

        // create two echo servers as endpoints
        let echo = echo_server().await;

        // filter config
        let mut map = Mapping::new();
        map.insert(Value::from("id"), Value::from("server"));
        // create server configuration
        let server_port = 12247;
        let server_config = Config {
            local: Local { port: server_port },
            filters: vec![Filter {
                name: factory.name(),
                config: Some(serde_yaml::Value::Mapping(map)),
            }],
            connections: ConnectionConfig::Server {
                endpoints: vec![EndPoint {
                    name: "server".to_string(),
                    address: echo,
                    connection_ids: vec![],
                }],
            },
        };
        let close_server = run_proxy(default_registry(&base_logger), server_config);

        let mut map = Mapping::new();
        map.insert(Value::from("id"), Value::from("client"));
        // create a local client
        let client_port = 12248;
        let client_config = Config {
            local: Local { port: client_port },
            filters: vec![Filter {
                name: factory.name(),
                config: Some(serde_yaml::Value::Mapping(map)),
            }],
            connections: ConnectionConfig::Client {
                addresses: vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    server_port,
                )],
                connection_id: "".into(),
                lb_policy: None,
            },
        };
        let close_client = run_proxy(default_registry(&base_logger), client_config);

        // let's send the packet
        let (mut recv_chan, mut send) = recv_multiple_packets(&base_logger).await;

        // game client
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
        info!(base_logger, "Sending hello"; "addr" => local_addr);
        send.send_to("hello".as_bytes(), &local_addr).await.unwrap();

        // since the debug filter doesn't change the data, it should be exactly the same
        assert_eq!("hello", recv_chan.recv().await.unwrap());

        close_server();
        close_client();
    }
}
