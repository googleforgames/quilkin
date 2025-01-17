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
    filters::{Compress, StaticFilter},
    net::endpoint::Endpoint,
    test::{AddressType, TestHelper},
};

#[tokio::test]
#[cfg_attr(target_os = "macos", ignore)]
async fn client_and_server() {
    let mut t = TestHelper::default();
    tokio::spawn(async move {
        let echo = t.run_echo_server(AddressType::Random).await;

        // create server configuration as
        let yaml = "
on_read: DECOMPRESS
on_write: COMPRESS
";
        let server_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
        server_config
            .clusters
            .modify(|clusters| clusters.insert_default([Endpoint::new(echo.clone())].into()));
        server_config.filters.store(
            quilkin::filters::FilterChain::try_create([Filter {
                name: Compress::factory().name().into(),
                label: None,
                config: serde_yaml::from_str(yaml).unwrap(),
            }])
            .map(std::sync::Arc::new)
            .unwrap(),
        );
        // Run server proxy.
        let server_port = t.run_server(server_config, None, None).await;

        // create a local client
        let yaml = "
on_read: COMPRESS
on_write: DECOMPRESS
";
        let client_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
        client_config.clusters.modify(|clusters| {
            clusters.insert_default([(std::net::Ipv6Addr::LOCALHOST, server_port).into()].into())
        });
        client_config.filters.store(
            quilkin::filters::FilterChain::try_create([Filter {
                name: Compress::factory().name().into(),
                label: None,
                config: serde_yaml::from_str(yaml).unwrap(),
            }])
            .map(std::sync::Arc::new)
            .unwrap(),
        );
        // Run client proxy.
        let client_port = t.run_server(client_config, None, None).await;

        // let's send the packet
        let (mut rx, tx) = t.open_socket_and_recv_multiple_packets().await;

        tx.send_to(b"hello", (std::net::Ipv6Addr::LOCALHOST, client_port))
            .await
            .unwrap();
        let expected = timeout(Duration::from_millis(500), rx.recv())
            .await
            .expect("should have received a packet")
            .unwrap();
        assert_eq!("hello", expected);
    });
}
