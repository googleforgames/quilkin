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

    use tokio::select;
    use tokio::time::{delay_for, Duration};

    use quilkin::config::{Config, ConnectionConfig, EndPoint, Local};
    use quilkin::extensions::default_registry;
    use quilkin::test_utils::{echo_server, logger, recv_multiple_packets, run_proxy};

    #[tokio::test]
    async fn echo() {
        let base_logger = logger();

        // create two echo servers as endpoints
        let server1 = echo_server().await;
        let server2 = echo_server().await;

        // create server configuration
        let server_port = 12345;
        let server_config = Config {
            local: Local { port: server_port },
            filters: vec![],
            connections: ConnectionConfig::Server {
                endpoints: vec![
                    EndPoint {
                        name: "server1".to_string(),
                        address: server1,
                        connection_ids: vec![],
                    },
                    EndPoint {
                        name: "server2".to_string(),
                        address: server2,
                        connection_ids: vec![],
                    },
                ],
            },
        };
        assert_eq!(Ok(()), server_config.validate());

        let close_server = run_proxy(default_registry(&base_logger), server_config);

        // create a local client
        let client_port = 12344;
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
        assert_eq!(Ok(()), client_config.validate());

        let close_client = run_proxy(default_registry(&base_logger), client_config);

        // let's send the packet
        let (mut recv_chan, mut send) = recv_multiple_packets(&base_logger).await;

        // game_client
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
        send.send_to("hello".as_bytes(), &local_addr).await.unwrap();

        assert_eq!("hello", recv_chan.recv().await.unwrap());
        assert_eq!("hello", recv_chan.recv().await.unwrap());

        // should only be two returned items
        select! {
            res = recv_chan.recv() => {
                assert!(false, format!("Should not receive a third packet: {}", res.unwrap()));
            }
            _ = delay_for(Duration::from_secs(2)) => {}
        };
        close_server();
        close_client();
    }
}
