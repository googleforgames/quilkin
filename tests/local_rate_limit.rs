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

extern crate quilkin;

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use quilkin::config::{Config, ConnectionConfig, EndPoint, Filter, Local};
    use quilkin::extensions::filters::RateLimitFilterFactory;
    use quilkin::extensions::{default_registry, FilterFactory};
    use quilkin::test_utils::{echo_server, logger, recv_multiple_packets, run_proxy};

    #[tokio::test]
    async fn local_rate_limit_filter() {
        let base_logger = logger();

        let yaml = "
max_packets: 2
period: 1s
";
        let echo = echo_server().await;

        let server_port = 12346;
        let server_config = Config {
            local: Local { port: server_port },
            filters: vec![Filter {
                name: RateLimitFilterFactory::default().name(),
                config: serde_yaml::from_str(yaml).unwrap(),
            }],
            connections: ConnectionConfig::Server {
                endpoints: vec![EndPoint {
                    name: "server".to_string(),
                    address: echo,
                    connection_ids: vec![],
                }],
            },
        };

        let close_server = run_proxy(default_registry(&base_logger), server_config);

        let (mut recv_chan, mut send) = recv_multiple_packets(&base_logger).await;

        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);

        for _ in 0..3 {
            send.send_to("hello".as_bytes(), &server_addr)
                .await
                .unwrap();
        }

        for _ in 0..2 {
            assert_eq!(recv_chan.recv().await.unwrap(), "hello");
        }

        // Allow enough time to have received any response.
        tokio::time::delay_for(std::time::Duration::from_millis(100)).await;
        // Check that we do not get any response.
        assert!(recv_chan.try_recv().is_err());

        close_server();
    }
}
