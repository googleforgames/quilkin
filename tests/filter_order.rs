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

///! Complex integration tests that incorporate multiple elements
use std::{net::SocketAddr, str::from_utf8};

use tokio::time::{timeout, Duration};

use quilkin::{
    config::{Builder, Filter},
    endpoint::Endpoint,
    filters::{compress, concatenate_bytes},
    test_utils::TestHelper,
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

    let echo = t
        .run_echo_server_with_tap(move |_, bytes, _| {
            assert!(
                from_utf8(bytes).is_err(),
                "Should be compressed, and therefore unable to be turned into a string"
            );
        })
        .await;

    let server_port = 12346;
    let server_config = Builder::empty()
        .with_port(server_port)
        .with_static(
            vec![
                Filter {
                    name: concatenate_bytes::factory().name().into(),
                    config: serde_yaml::from_str(yaml_concat_read).unwrap(),
                },
                Filter {
                    name: concatenate_bytes::factory().name().into(),
                    config: serde_yaml::from_str(yaml_concat_write).unwrap(),
                },
                Filter {
                    name: compress::factory(&t.log).name().into(),
                    config: serde_yaml::from_str(yaml_compress).unwrap(),
                },
            ],
            vec![Endpoint::new(echo)],
        )
        .build();

    t.run_server_with_config(server_config);

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    let local_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();
    socket.send_to(b"hello", &local_addr).await.unwrap();

    assert_eq!(
        "helloxyzabc",
        timeout(Duration::from_secs(5), recv_chan.recv())
            .await
            .expect("should have received a packet")
            .unwrap()
    );
}
