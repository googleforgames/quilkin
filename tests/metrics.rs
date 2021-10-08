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

use slog::info;

use quilkin::{
    config::{Admin, Builder as ConfigBuilder},
    endpoint::Endpoint,
    test_utils::TestHelper,
    Builder,
};

#[tokio::test]
async fn metrics_server() {
    let mut t = TestHelper::default();

    // create an echo server as an endpoint.
    let echo = t.run_echo_server().await;

    // create server configuration
    let server_port = 12346;
    let server_config = ConfigBuilder::empty()
        .with_port(server_port)
        .with_static(vec![], vec![Endpoint::new(echo)])
        .with_admin(Admin {
            address: "[::]:9092".parse().unwrap(),
        })
        .build();
    t.run_server_with_builder(Builder::from(Arc::new(server_config)));

    // create a local client
    let client_port = 12347;
    let client_config = ConfigBuilder::empty()
        .with_port(client_port)
        .with_static(
            vec![],
            vec![Endpoint::new(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                server_port,
            ))],
        )
        .build();
    t.run_server_with_builder(Builder::from(Arc::new(client_config)));

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    // game_client
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
    info!(t.log, "Sending hello"; "address" => local_addr);
    socket.send_to(b"hello", &local_addr).await.unwrap();

    let _ = recv_chan.recv().await.unwrap();

    let resp = reqwest::get("http://localhost:9092/metrics")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(resp.contains("quilkin_session_tx_packets_total 1"));
}
