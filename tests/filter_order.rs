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

use std::{net::Ipv4Addr, str::from_utf8};

use tokio::time::{timeout, Duration};

use quilkin::{
    config::Filter,
    filters::{Compress, Concatenate, StaticFilter},
    net::endpoint::Endpoint,
    test::{AddressType, TestHelper},
};

#[tokio::test]
async fn filter_order() {
    let mut t = TestHelper::default();

    let yaml_concat_read = "
on_read: APPEND
bytes: eHl6 #xyz
";

    let yaml_concat_write = "
on_write: APPEND
bytes: YWJj #abc
";

    let yaml_compress = "
on_read: COMPRESS
on_write: DECOMPRESS
";

    let mut echo = t
        .run_echo_server_with_tap(&AddressType::Random, move |_, bytes, _| {
            assert!(
                from_utf8(bytes).is_err(),
                "Should be compressed, and therefore unable to be turned into a string"
            );
        })
        .await;

    quilkin::test::map_to_localhost(&mut echo).await;
    let server_config = std::sync::Arc::new(quilkin::Config::default());
    server_config
        .clusters
        .modify(|clusters| clusters.insert_default([Endpoint::new(echo.clone())].into()));
    server_config.filters.store(
        quilkin::filters::FilterChain::try_from(vec![
            Filter {
                name: Concatenate::factory().name().into(),
                label: None,
                config: serde_yaml::from_str(yaml_concat_read).unwrap(),
            },
            Filter {
                name: Concatenate::factory().name().into(),
                label: None,
                config: serde_yaml::from_str(yaml_concat_write).unwrap(),
            },
            Filter {
                name: Compress::factory().name().into(),
                label: None,
                config: serde_yaml::from_str(yaml_compress).unwrap(),
            },
        ])
        .map(std::sync::Arc::new)
        .unwrap(),
    );

    let server_port = t.run_server(server_config, None, None).await;

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    let local_addr = (Ipv4Addr::LOCALHOST, server_port);
    socket.send_to(b"hello", &local_addr).await.unwrap();

    assert_eq!(
        "helloxyzabc",
        timeout(Duration::from_millis(500), recv_chan.recv())
            .await
            .expect("should have received a packet")
            .unwrap()
    );
}
