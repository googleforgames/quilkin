/*
 * Copyright 2021 Google LLC
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

use tokio::time::{timeout, Duration};

use quilkin::{
    config::Filter,
    endpoint::Endpoint,
    filters::{Compress, StaticFilter},
    test_utils::{available_addr, AddressType, TestHelper},
};

#[tokio::test]
async fn client_and_server() {
    let mut t = TestHelper::default();
    let echo = t.run_echo_server(&AddressType::Random).await;

    // create server configuration as
    let mut server_addr = available_addr(&AddressType::Random).await;
    quilkin::test_utils::map_addr_to_localhost(&mut server_addr);
    let yaml = "
on_read: DECOMPRESS
on_write: COMPRESS
";
    let server_config = std::sync::Arc::new(quilkin::Config::default());
    server_config
        .clusters
        .modify(|clusters| clusters.insert_default([Endpoint::new(echo.clone())].into()));
    server_config.filters.store(
        quilkin::filters::FilterChain::try_from(vec![Filter {
            name: Compress::factory().name().into(),
            label: None,
            config: serde_yaml::from_str(yaml).unwrap(),
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );
    let server_proxy = quilkin::cli::Proxy {
        port: server_addr.port(),
        ..<_>::default()
    };
    // Run server proxy.
    t.run_server(server_config, server_proxy, None);

    // create a local client
    let client_addr = available_addr(&AddressType::Random).await;
    let yaml = "
on_read: COMPRESS
on_write: DECOMPRESS
";
    let client_config = std::sync::Arc::new(quilkin::Config::default());
    client_config
        .clusters
        .modify(|clusters| clusters.insert_default([Endpoint::new(server_addr.into())].into()));
    client_config.filters.store(
        quilkin::filters::FilterChain::try_from(vec![Filter {
            name: Compress::factory().name().into(),
            label: None,
            config: serde_yaml::from_str(yaml).unwrap(),
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );
    let client_proxy = quilkin::cli::Proxy {
        port: client_addr.port(),
        ..<_>::default()
    };
    // Run client proxy.
    t.run_server(client_config, client_proxy, None);

    // let's send the packet
    let (mut rx, tx) = t.open_socket_and_recv_multiple_packets().await;

    tx.send_to(b"hello", &client_addr).await.unwrap();
    let expected = timeout(Duration::from_millis(500), rx.recv())
        .await
        .expect("should have received a packet")
        .unwrap();
    assert_eq!("hello", expected);
}
