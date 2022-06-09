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

use quilkin::test_utils::available_addr;
use quilkin::{
    config::Filter,
    endpoint::Endpoint,
    filters::{Compress, StaticFilter},
    test_utils::TestHelper,
};

#[tokio::test]
async fn client_and_server() {
    let mut t = TestHelper::default();
    let echo = t.run_echo_server().await;

    // create server configuration as
    let server_addr = available_addr().await;
    let yaml = "
on_read: DECOMPRESS
on_write: COMPRESS
";
    let server_config = quilkin::Server::builder()
        .port(server_addr.port())
        .filters(vec![Filter {
            name: Compress::factory().name().into(),
            config: serde_yaml::from_str(yaml).unwrap(),
        }])
        .endpoints(vec![Endpoint::new(echo)])
        .build()
        .unwrap();
    // Run server proxy.
    t.run_server_with_config(server_config);

    // create a local client
    let client_addr = available_addr().await;
    let yaml = "
on_read: COMPRESS
on_write: DECOMPRESS
";
    let client_config = quilkin::Server::builder()
        .port(client_addr.port())
        .filters(vec![Filter {
            name: Compress::factory().name().into(),
            config: serde_yaml::from_str(yaml).unwrap(),
        }])
        .endpoints(vec![Endpoint::new(server_addr.into())])
        .build()
        .unwrap();
    // Run client proxy.
    t.run_server_with_config(client_config);

    // let's send the packet
    let (mut rx, tx) = t.open_socket_and_recv_multiple_packets().await;

    tx.send_to(b"hello", &client_addr).await.unwrap();
    let expected = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("should have received a packet")
        .unwrap();
    assert_eq!("hello", expected);
}
