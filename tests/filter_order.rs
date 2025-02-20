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

use std::net::Ipv4Addr;

use tokio::time::{timeout, Duration};

use quilkin::{
    config::Filter,
    net::endpoint::Endpoint,
    test::{AddressType, TestHelper},
};

#[tokio::test]
#[cfg_attr(target_os = "macos", ignore)]
async fn multiple_mutations() {
    let filters = r#"
- name: quilkin.filters.capture.v1alpha1.Capture
  config:
    metadataKey: embark.dev/load_balancer/version
    suffix:
      size: 1
      remove: true
- name: quilkin.filters.capture.v1alpha1.Capture
  config:
    metadataKey: embark.dev/load_balancer/token
    suffix:
      size: 16
      remove: true
"#;

    let filters: Vec<Filter> = serde_yaml::from_str(filters).unwrap();

    let mut t = TestHelper::default();
    let mut echo = t
        .run_echo_server_with_tap(AddressType::Random, move |_, bytes, _| {
            assert_eq!(b"hello", bytes);
        })
        .await;

    quilkin::test::map_to_localhost(&mut echo);
    let server_config = std::sync::Arc::new(quilkin::Config::default_non_agent());
    server_config
        .dyn_cfg
        .clusters()
        .unwrap()
        .modify(|clusters| clusters.insert_default([Endpoint::new(echo.clone())].into()));
    server_config.dyn_cfg.filters().unwrap().store(
        quilkin::filters::FilterChain::try_create(filters)
            .map(std::sync::Arc::new)
            .unwrap(),
    );

    let server_port = t.run_server(server_config, None, None).await;

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    let local_addr = (Ipv4Addr::LOCALHOST, server_port);

    socket
        .send_to(b"helloxxxxxxxxxxxxxxxx6", &local_addr)
        .await
        .unwrap();

    let received = timeout(Duration::from_millis(500), recv_chan.recv())
        .await
        .expect("should have received a packet")
        .unwrap();

    assert_eq!(b"hello", received.as_bytes());
}
