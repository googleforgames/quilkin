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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::time::{timeout, Duration};

use quilkin::{
    config::Filter,
    filters::{Capture, StaticFilter, TokenRouter},
    net::endpoint::{metadata::MetadataView, Endpoint},
    test::{AddressType, TestHelper},
};

/// This test covers both token_router and capture filters,
/// since they work in concert together.
#[tokio::test]
#[cfg_attr(target_os = "macos", ignore)]
async fn token_router() {
    let mut t = TestHelper::default();
    let mut echo = t.run_echo_server(AddressType::Random).await;
    quilkin::test::map_to_localhost(&mut echo);

    let server_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
    server_config.filters.store(
        quilkin::filters::FilterChain::try_create([
            Filter {
                name: Capture::factory().name().into(),
                label: None,
                config: serde_json::from_value(serde_json::json!({
                    "regex": {
                        "pattern": ".{3}$"
                    }
                }))
                .unwrap(),
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

    server_config.clusters.modify(|clusters| {
        clusters.insert_default(
            [Endpoint::with_metadata(
                echo.clone(),
                serde_json::from_value::<MetadataView<_>>(serde_json::json!({
                    "quilkin.dev": {
                        "tokens": ["YWJj"]
                    }
                }))
                .unwrap(),
            )]
            .into(),
        )
    });

    let server_port = t.run_server(server_config, None, None).await;

    // valid packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);
    let msg = b"helloabc";
    socket.send_to(msg, &local_addr).await.unwrap();

    assert_eq!(
        "helloabc",
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
