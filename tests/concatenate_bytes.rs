/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use tokio::time::{timeout, Duration};

    use quilkin::config::{Builder, EndPoint, Filter};
    use quilkin::extensions::filters::ConcatBytesFactory;
    use quilkin::extensions::FilterFactory;
    use quilkin::test_utils::TestHelper;

    #[tokio::test]
    async fn concatenate_bytes() {
        let mut t = TestHelper::default();
        let yaml = "
on_read: APPEND
bytes: YWJj #abc
";
        let echo = t.run_echo_server().await;

        let server_port = 12346;
        let server_config = Builder::empty()
            .with_port(server_port)
            .with_static(
                vec![Filter {
                    name: ConcatBytesFactory::default().name(),
                    config: serde_yaml::from_str(yaml).unwrap(),
                }],
                vec![EndPoint::new(echo)],
            )
            .build();

        t.run_server(server_config);

        // let's send the packet
        let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);
        socket.send_to(b"hello", &local_addr).await.unwrap();

        assert_eq!(
            "helloabc",
            timeout(Duration::from_secs(5), recv_chan.recv())
                .await
                .expect("should have received a packet")
                .unwrap()
        );
    }
}
