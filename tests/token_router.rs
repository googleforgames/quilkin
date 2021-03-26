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

    use tokio::time::{timeout, Duration};

    use quilkin::config::{Builder, EndPoint, Filter};
    use quilkin::extensions::filters::{CaptureBytesFactory, TokenRouterFactory};
    use quilkin::extensions::FilterFactory;
    use quilkin::proxy::Builder as ProxyBuilder;
    use quilkin::test_utils::{logger, TestHelper};
    use std::sync::Arc;

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
        let endpoint_metadata = "
quilkin.dev:
    tokens:
        - YWJj # abc
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
                vec![EndPoint::with_metadata(
                    echo,
                    Some(serde_yaml::from_str(endpoint_metadata).unwrap()),
                )],
            )
            .build();
        t.run_server(ProxyBuilder::from(Arc::new(server_config)).disable_admin());

        // valid packet
        let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);
        let msg = b"helloabc";
        socket.send_to(msg, &local_addr).await.unwrap();

        assert_eq!(
            "hello",
            timeout(Duration::from_secs(5), recv_chan.recv())
                .await
                .expect("should have received a packet")
                .unwrap()
        );

        // send an invalid packet
        let msg = b"helloxyz";
        socket.send_to(msg, &local_addr).await.unwrap();

        let result = timeout(Duration::from_secs(3), recv_chan.recv()).await;
        assert!(result.is_err(), "should not have received a packet");
    }
}
