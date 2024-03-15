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
    time::Duration,
};
use tokio::time::timeout;

use quilkin::{
    config::Filter,
    filters::{Debug, StaticFilter},
    net::endpoint::Endpoint,
    test::{load_test_filters, AddressType, TestHelper},
};

#[tokio::test]
async fn test_filter() {
    let mut t = TestHelper::default();
    load_test_filters();

    // create an echo server as an endpoint.
    let echo = t.run_echo_server(AddressType::Random).await;

    // create server configuration
    let server_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
    server_config.filters.store(
        quilkin::filters::FilterChain::try_create([Filter {
            name: "TestFilter".to_string(),
            label: None,
            config: None,
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );

    server_config
        .clusters
        .modify(|clusters| clusters.insert_default([Endpoint::new(echo.clone())].into()));

    let server_port = t.run_server(server_config, None, None).await;

    // create a local client
    let client_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
    client_config.clusters.modify(|clusters| {
        clusters.insert_default(
            [Endpoint::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port).into(),
            )]
            .into(),
        )
    });
    client_config.filters.store(
        quilkin::filters::FilterChain::try_create([Filter {
            name: "TestFilter".to_string(),
            label: None,
            config: None,
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );

    // Run client proxy.
    let client_port = t.run_server(client_config, None, None).await;

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    // game_client
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
    tracing::info!(address = %local_addr, "Sending hello");
    socket.send_to(b"hello", &local_addr).await.unwrap();

    let result = timeout(Duration::from_secs(5), recv_chan.recv())
        .await
        .unwrap()
        .unwrap();
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
    let factory = Debug::factory();

    // create an echo server as an endpoint.
    let echo = t.run_echo_server(AddressType::Random).await;

    tracing::trace!(%echo, "running echo server");
    // create server configuration
    let server_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
    server_config
        .clusters
        .modify(|clusters| clusters.insert_default([Endpoint::new(echo.clone())].into()));
    server_config.filters.store(
        quilkin::filters::FilterChain::try_create([Filter {
            name: factory.name().into(),
            label: None,
            config: Some(serde_json::json!({ "id":  "server", })),
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );

    let server_port = t.run_server(server_config, None, None).await;

    // create a local client
    let client_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
    client_config.clusters.modify(|clusters| {
        clusters.insert_default(
            [Endpoint::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port).into(),
            )]
            .into(),
        )
    });
    client_config.filters.store(
        quilkin::filters::FilterChain::try_create([Filter {
            name: factory.name().into(),
            label: None,
            config: Some(serde_json::json!({ "id":  "client" })),
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );
    let client_port = t.run_server(client_config, None, None).await;

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    // game client
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
    tracing::info!(address = %local_addr, "Sending hello");
    socket.send_to(b"hello", &local_addr).await.unwrap();

    // since the debug filter doesn't change the data, it should be exactly the same
    let value = timeout(Duration::from_millis(500), recv_chan.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!("hello", value);
}
