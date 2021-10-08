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

use std::net::SocketAddr;

use slog::info;
use tokio::time::{timeout, Duration};

use quilkin::{
    config::{Builder, Filter},
    endpoint::Endpoint,
    filters::compress,
    test_utils::{logger, TestHelper},
};

#[tokio::test]
async fn client_and_server() {
    let log = logger();
    let mut t = TestHelper::default();
    let echo = t.run_echo_server().await;

    // create server configuration as
    let server_port = 12356;
    let yaml = "
on_read: DECOMPRESS
on_write: COMPRESS
";
    let server_config = Builder::empty()
        .with_port(server_port)
        .with_static(
            vec![Filter {
                name: compress::factory(&log).name().into(),
                config: serde_yaml::from_str(yaml).unwrap(),
            }],
            vec![Endpoint::new(echo)],
        )
        .build();
    // Run server proxy.
    t.run_server_with_config(server_config);

    // create a local client
    let client_port = 12357;
    let yaml = "
on_read: COMPRESS
on_write: DECOMPRESS
";
    let client_config = Builder::empty()
        .with_port(client_port)
        .with_static(
            vec![Filter {
                name: compress::factory(&log).name().into(),
                config: serde_yaml::from_str(yaml).unwrap(),
            }],
            vec![Endpoint::new(
                format!("127.0.0.1:{}", server_port).parse().unwrap(),
            )],
        )
        .build();
    // Run client proxy.
    t.run_server_with_config(client_config);

    // let's send the packet
    let (mut rx, tx) = t.open_socket_and_recv_multiple_packets().await;

    // game_client
    let local_addr: SocketAddr = format!("127.0.0.1:{}", client_port).parse().unwrap();
    info!(t.log, "Sending hello"; "address" => local_addr);
    tx.send_to(b"hello", &local_addr).await.unwrap();

    let expected = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("should have received a packet")
        .unwrap();
    assert_eq!("hello", expected);
}
