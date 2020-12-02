/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use slog::debug;
    use tokio::select;
    use tokio::time::{delay_for, Duration};

    use quilkin::config::{Builder, ConnectionId, EndPoint, Filter};
    use quilkin::extensions::filters::{CaptureBytesFactory, TokenRouterFactory};
    use quilkin::extensions::FilterFactory;
    use quilkin::test_utils::{logger, TestHelper};

    /// This test covers both token_router and capture_bytes filters,
    /// since they work in concert together.
    #[tokio::test]
    async fn token_router() {
        let log = logger();
        let mut t = TestHelper::default();
        let echo = t.run_echo_server().await;

        let capture_yaml = "
size: 3
remove: true
";
        let server_port = 12348;
        let server_config = Builder::empty()
            .with_port(server_port)
            .with_static(
                vec![
                    Filter {
                        name: CaptureBytesFactory::new(&log).name(),
                        config: serde_yaml::from_str(capture_yaml).unwrap(),
                    },
                    Filter {
                        name: TokenRouterFactory::new(&log).name(),
                        config: None,
                    },
                ],
                vec![EndPoint {
                    name: "server".to_string(),
                    address: echo,
                    connection_ids: vec![ConnectionId::from("abc")],
                }],
            )
            .build();
        server_config.validate().unwrap();
        t.run_server(server_config);

        // valid packet
        let (mut recv_chan, mut send) = t.open_socket_and_recv_multiple_packets().await;

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);
        let msg = b"helloabc";
        debug!(log, "sending message"; "content" => format!("{:?}", msg));
        send.send_to(msg, &local_addr).await.unwrap();

        select! {
            res = recv_chan.recv() => {
                assert_eq!("hello", res.unwrap());
            }
            _ = delay_for(Duration::from_secs(5)) => {
                unreachable!("should have received a packet");
            }
        };

        // send an invalid packet
        let msg = b"helloxyz";
        debug!(log, "sending message"; "content" => format!("{:?}", msg));
        send.send_to(msg, &local_addr).await.unwrap();

        select! {
            _ = recv_chan.recv() => {
                unreachable!("should not have received a packet")
            }
            _ = delay_for(Duration::from_secs(3)) => {}
        };
    }
}
