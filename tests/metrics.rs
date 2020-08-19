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

    use prometheus::Registry;
    use regex::Regex;
    use slog::info;

    use quilkin::config::{Config, ConnectionConfig, EndPoint, Local};
    use quilkin::extensions::FilterRegistry;
    use quilkin::proxy::Metrics;
    use quilkin::test_utils::{
        echo_server, logger, recv_multiple_packets, run_proxy, run_proxy_with_metrics,
    };

    #[tokio::test]
    async fn metrics_server() {
        let base_logger = logger();
        let server_metrics = Metrics::new(Some("[::]:9092".parse().unwrap()), Registry::default());

        // create two echo servers as endpoints
        let echo = echo_server().await;

        // create server configuration
        let server_port = 12346;
        let server_config = Config {
            local: Local { port: server_port },
            filters: vec![],
            connections: ConnectionConfig::Server {
                endpoints: vec![EndPoint {
                    name: "server".to_string(),
                    address: echo,
                    connection_ids: vec![],
                }],
            },
        };

        let close_server = run_proxy_with_metrics(
            &base_logger,
            FilterRegistry::default(),
            server_config,
            server_metrics,
        );

        // create a local client
        let client_port = 12347;
        let client_config = Config {
            local: Local { port: client_port },
            filters: vec![],
            connections: ConnectionConfig::Client {
                addresses: vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    server_port,
                )],
                connection_id: "".into(),
                lb_policy: None,
            },
        };
        let close_client = run_proxy(&base_logger, FilterRegistry::default(), client_config);

        // let's send the packet
        let (mut recv_chan, mut send) = recv_multiple_packets(&base_logger).await;

        // game_client
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
        info!(base_logger, "Sending hello"; "addr" => local_addr);
        send.send_to("hello".as_bytes(), &local_addr).await.unwrap();

        let _ = recv_chan.recv().await.unwrap();

        let resp = reqwest::get("http://localhost:9092/metrics")
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        let re =
            Regex::new(r#"quilkin_session_tx_packets_total\{downstream="(.*)",upstream="(.*)"} 1"#)
                .unwrap();
        assert!(re.is_match(&resp));

        for c in re.captures_iter(&resp) {
            let downstream = (&c[1]).parse::<SocketAddr>().unwrap();
            let upstream = (&c[2]).parse::<SocketAddr>().unwrap();
            assert_ne!(downstream, upstream);
        }

        close_server();
        close_client();
    }
}
