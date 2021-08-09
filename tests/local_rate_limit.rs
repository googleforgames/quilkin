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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::time::{timeout, Duration};

use quilkin::{
    config::{Builder as ConfigBuilder, Filter},
    endpoint::Endpoint,
    filters::local_rate_limit,
    test_utils::TestHelper,
};

#[tokio::test]
async fn local_rate_limit_filter() {
    let mut t = TestHelper::default();

    let yaml = "
max_packets: 2
period: 1s
";
    let echo = t.run_echo_server().await;

    let server_port = 12346;
    let server_config = ConfigBuilder::empty()
        .with_port(server_port)
        .with_static(
            vec![Filter {
                name: local_rate_limit::factory().name().into(),
                config: serde_yaml::from_str(yaml).unwrap(),
            }],
            vec![Endpoint::new(echo)],
        )
        .build();
    t.run_server_with_config(server_config);

    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);

    for _ in 0..3 {
        socket.send_to(b"hello", &server_addr).await.unwrap();
    }

    for _ in 0..2 {
        assert_eq!(recv_chan.recv().await.unwrap(), "hello");
    }

    // Allow enough time to have received any response.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Check that we do not get any response.
    assert!(timeout(Duration::from_secs(1), recv_chan.recv())
        .await
        .is_err());
}
