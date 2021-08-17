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

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use serde_yaml::{Mapping, Value};
use slog::info;

use quilkin::{
    config::{Builder as ConfigBuilder, Filter},
    endpoint::Endpoint,
    filters::debug,
    test_utils::{new_registry, TestHelper},
    Builder as ProxyBuilder,
};

#[tokio::test]
async fn test_filter() {
    let mut t = TestHelper::default();

    // create an echo server as an endpoint.
    let echo = t.run_echo_server().await;

    // create server configuration
    let server_port = 12346;
    let server_config = ConfigBuilder::empty()
        .with_port(server_port)
        .with_static(
            vec![Filter {
                name: "TestFilter".to_string(),
                config: None,
            }],
            vec![Endpoint::new(echo)],
        )
        .build();

    // Run server proxy.
    let registry = new_registry(&t.log);
    t.run_server_with_builder(
        ProxyBuilder::from(Arc::new(server_config))
            .with_filter_registry(registry)
            .disable_admin(),
    );

    // create a local client
    let client_port = 12347;
    let client_config = ConfigBuilder::empty()
        .with_port(client_port)
        .with_static(
            vec![Filter {
                name: "TestFilter".to_string(),
                config: None,
            }],
            vec![Endpoint::new(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                server_port,
            ))],
        )
        .build();

    // Run client proxy.
    let registry = new_registry(&t.log);
    t.run_server_with_builder(
        ProxyBuilder::from(Arc::new(client_config))
            .with_filter_registry(registry)
            .disable_admin(),
    );

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    // game_client
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
    info!(t.log, "Sending hello"; "address" => local_addr);
    socket.send_to(b"hello", &local_addr).await.unwrap();

    let result = recv_chan.recv().await.unwrap();
    // since we don't know the ephemeral ip addresses in use, we'll search for
    // substrings for the results we expect that the TestFilter will inject in
    // the round-tripped packets.
    assert_eq!(
        2,
        result.matches("odr").count(),
        "Should be 2 read calls in {}",
        result
    );
    assert_eq!(
        2,
        result.matches("our").count(),
        "Should be 2 write calls in {}",
        result
    );
}

#[tokio::test]
async fn debug_filter() {
    let mut t = TestHelper::default();

    // handy for grabbing the configuration name
    let factory = debug::factory(&t.log);

    // create an echo server as an endpoint.
    let echo = t.run_echo_server().await;

    // filter config
    let mut map = Mapping::new();
    map.insert(Value::from("id"), Value::from("server"));
    // create server configuration
    let server_port = 12247;
    let server_config = ConfigBuilder::empty()
        .with_port(server_port)
        .with_static(
            vec![Filter {
                name: factory.name().into(),
                config: Some(serde_yaml::Value::Mapping(map)),
            }],
            vec![Endpoint::new(echo)],
        )
        .build();
    t.run_server_with_config(server_config);

    let mut map = Mapping::new();
    map.insert(Value::from("id"), Value::from("client"));
    // create a local client
    let client_port = 12248;
    let client_config = ConfigBuilder::empty()
        .with_port(client_port)
        .with_static(
            vec![Filter {
                name: factory.name().into(),
                config: Some(serde_yaml::Value::Mapping(map)),
            }],
            vec![Endpoint::new(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                server_port,
            ))],
        )
        .build();
    t.run_server_with_config(client_config);

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    // game client
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
    info!(t.log, "Sending hello"; "address" => local_addr);
    socket.send_to(b"hello", &local_addr).await.unwrap();

    // since the debug filter doesn't change the data, it should be exactly the same
    assert_eq!("hello", recv_chan.recv().await.unwrap());
}
