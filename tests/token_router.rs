/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::net::{Ipv6Addr, SocketAddr};

use quilkin::{
    config::Filter,
    filters::{Capture, StaticFilter, TokenRouter},
    net::endpoint::{metadata::MetadataView, Endpoint},
    test::{AddressType, TestHelper},
};
use tokio::time::{timeout, Duration};

/// This test covers both token_router and capture filters,
/// since they work in concert together.
#[tokio::test]
async fn token_router() {
    let mut t = TestHelper::default();

    let local_addr = echo_server(&mut t).await;

    // valid packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    let msg = b"helloabc";
    tracing::trace!(%local_addr, "sending echo packet");
    socket.send_to(msg, &local_addr).await.unwrap();

    tracing::trace!("awaiting echo packet");
    assert_eq!(
        "hello",
        timeout(Duration::from_millis(500), recv_chan.recv())
            .await
            .expect("should have received a packet")
            .unwrap()
    );

    // send an invalid packet
    let msg = b"helloxyz";
    socket.send_to(msg, &local_addr).await.unwrap();

    let result = timeout(Duration::from_millis(500), recv_chan.recv()).await;
    assert!(result.is_err(), "should not have received a packet");
}

// This test covers the scenario in https://github.com/googleforgames/quilkin/issues/988
// to make sure there are no issues with overlapping streams between clients.
#[tokio::test]
async fn multiple_clients() {
    let limit = 10_000;
    let mut t = TestHelper::default();
    let local_addr = echo_server(&mut t).await;

    let (mut a_rx, a_socket) = t.open_socket_and_recv_multiple_packets().await;
    let (mut b_rx, b_socket) = t.open_socket_and_recv_multiple_packets().await;

    tokio::spawn(async move {
        // some room to breath
        tokio::time::sleep(Duration::from_millis(50)).await;
        for _ in 0..limit {
            a_socket.send_to(b"Aabc", &local_addr).await.unwrap();
            tokio::time::sleep(Duration::from_nanos(5)).await;
        }
    });
    tokio::spawn(async move {
        // some room to breath
        tokio::time::sleep(Duration::from_millis(50)).await;
        for _ in 0..limit {
            b_socket.send_to(b"Babc", &local_addr).await.unwrap();
            tokio::time::sleep(Duration::from_nanos(5)).await;
        }
    });

    let mut success = 0;
    let mut failed = 0;
    for _ in 0..limit {
        match timeout(Duration::from_millis(60), a_rx.recv()).await {
            Ok(packet) => {
                assert_eq!("A", packet.unwrap());
                success += 1;
            }
            Err(_) => {
                failed += 1;
            }
        }
        match timeout(Duration::from_millis(60), b_rx.recv()).await {
            Ok(packet) => {
                assert_eq!("B", packet.unwrap());
                success += 1;
            }
            Err(_) => {
                failed += 1;
            }
        }
    }

    // allow for some dropped packets, since UDP.
    let threshold = 0.95 * (2 * limit) as f64;
    assert!(
        success as f64 > threshold,
        "Success: {}, Failed: {}",
        success,
        failed
    );
}

// start an echo server and return what port it's on.
async fn echo_server(t: &mut TestHelper) -> SocketAddr {
    let mut echo = t.run_echo_server(AddressType::Ipv6).await;
    quilkin::test::map_to_localhost(&mut echo);

    let capture_yaml = "
suffix:
    size: 3
    remove: true
";
    let endpoint_metadata = "
quilkin.dev:
    tokens:
        - YWJj # abc
        ";

    let server_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
    server_config.clusters.modify(|clusters| {
        clusters.insert_default(
            [
                Endpoint::with_metadata(
                    echo.clone(),
                    serde_yaml::from_str::<MetadataView<_>>(endpoint_metadata).unwrap(),
                ),
                "127.0.0.2:5000".parse().unwrap(), // goes nowhere, so shouldn't do anything.
            ]
            .into(),
        )
    });

    server_config.filters.store(
        quilkin::filters::FilterChain::try_create([
            Filter {
                name: Capture::factory().name().into(),
                label: None,
                config: serde_yaml::from_str(capture_yaml).unwrap(),
            },
            Filter {
                name: TokenRouter::factory().name().into(),
                label: None,
                config: None,
            },
        ])
        .map(std::sync::Arc::new)
        .unwrap(),
    );

    let server_port = t.run_server(server_config, None, None).await;
    SocketAddr::from((Ipv6Addr::LOCALHOST, server_port))
}
