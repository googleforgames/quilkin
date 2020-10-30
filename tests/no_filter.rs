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
    use tokio::time::{sleep, Duration};

    use quilkin::config::{Builder as ConfigBuilder, ConnectionConfig, EndPoint, Local};
    use quilkin::test_utils::TestHelper;

    #[tokio::test]
    async fn echo() {
        let mut t = TestHelper::default();

        // create two echo servers as endpoints
        let server1 = t.run_echo_server().await;
        let server2 = t.run_echo_server().await;

        // create server configuration
        let server_port = 12345;
        let server_config = ConfigBuilder::empty()
            .with_local(Local { port: server_port })
            .with_connections(ConnectionConfig::Server {
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
            })
            .build();
        assert_eq!(Ok(()), server_config.validate());

        t.run_server(server_config);

        // create a local client
        let client_port = 12344;
        let client_config = ConfigBuilder::empty()
            .with_local(Local { port: client_port })
            .with_connections(ConnectionConfig::Client {
                addresses: vec![SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    server_port,
                )],
                lb_policy: None,
            })
            .build();
        assert_eq!(Ok(()), client_config.validate());

        t.run_server(client_config);

        // let's send the packet
        let (mut recv_chan, send) = t.open_socket_and_recv_multiple_packets().await;

        // game_client
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), client_port);
        send.send_to(b"hello", &local_addr).await.unwrap();

        assert_eq!("hello", recv_chan.recv().await.unwrap());
        assert_eq!("hello", recv_chan.recv().await.unwrap());

        // should only be two returned items
        select! {
            res = recv_chan.recv() => {
                unreachable!("Should not receive a third packet: {}", res.unwrap());
            }
            _ = sleep(Duration::from_secs(2)) => {}
        };
    }
}
