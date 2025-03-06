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

use std::net::Ipv4Addr;

use tokio::time::{Duration, timeout};

use quilkin::{
    config::Filter,
    filters::{Concatenate, StaticFilter},
    net::endpoint::Endpoint,
    test::{AddressType, TestHelper},
};

#[tokio::test]
#[cfg_attr(target_os = "macos", ignore)]
async fn concatenate() {
    let mut t = TestHelper::default();
    let yaml = "
on_read: APPEND
bytes: YWJj #abc
";
    let echo = t.run_echo_server(AddressType::Random).await;

    let server_config = std::sync::Arc::new(quilkin::Config::default());
    server_config
        .dyn_cfg
        .clusters()
        .unwrap()
        .modify(|clusters| clusters.insert_default([Endpoint::new(echo.clone())].into()));
    server_config.dyn_cfg.filters().unwrap().store(
        quilkin::filters::FilterChain::try_create([Filter {
            name: Concatenate::factory().name().into(),
            label: None,
            config: serde_yaml::from_str(yaml).unwrap(),
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );
    let server_port = t.run_server(server_config, None, None).await;

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    let local_addr = (Ipv4Addr::LOCALHOST, server_port);
    socket.send_to(b"hello", &local_addr).await.unwrap();

    assert_eq!(
        "helloabc",
        timeout(Duration::from_millis(250), recv_chan.recv())
            .await
            .expect("should have received a packet")
            .unwrap()
    );
}
