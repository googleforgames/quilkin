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

use std::time::Duration;

use tokio::time::timeout;

use quilkin::{
    config::Filter,
    filters::{LocalRateLimit, StaticFilter},
    net::endpoint::Endpoint,
    test::{available_addr, AddressType, TestHelper},
};

#[tokio::test]
async fn local_rate_limit_filter() {
    let mut t = TestHelper::default();

    let yaml = "
max_packets: 2
period: 1
";
    let echo = t.run_echo_server(&AddressType::Random).await;

    let mut server_addr = available_addr(&AddressType::Random).await;
    quilkin::test::map_addr_to_localhost(&mut server_addr);
    let server_proxy = quilkin::cli::Proxy {
        port: server_addr.port(),
        ..<_>::default()
    };
    let server_config = std::sync::Arc::new(quilkin::Config::default());
    server_config
        .clusters
        .modify(|clusters| clusters.insert_default([Endpoint::new(echo.clone())].into()));
    server_config.filters.store(
        quilkin::filters::FilterChain::try_from(vec![Filter {
            name: LocalRateLimit::factory().name().into(),
            label: None,
            config: serde_yaml::from_str(yaml).unwrap(),
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );
    tracing::trace!("spawning server");
    t.run_server(server_config, server_proxy, None);
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    let msg = "hello";
    let (mut rx, socket) = t.open_socket_and_recv_multiple_packets().await;

    for _ in 0..3 {
        tracing::trace!(%server_addr, %msg, "sending");
        socket.send_to(msg.as_bytes(), &server_addr).await.unwrap();
    }

    for _ in 0..2 {
        assert_eq!(
            msg,
            timeout(Duration::from_millis(500), rx.recv())
                .await
                .unwrap()
                .unwrap()
        );
    }

    // Allow enough time to have received any response.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Check that we do not get any response.
    assert!(timeout(Duration::from_millis(500), rx.recv())
        .await
        .is_err());
}
