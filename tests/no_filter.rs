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
    use std::str::from_utf8;
    use std::sync::Arc;

    use tokio::select;
    use tokio::sync::{mpsc, oneshot};

    use quilkin::config::{Config, ConnectionConfig, EndPoint, Local};
    use quilkin::extensions::default_filters;
    use quilkin::server::Server;
    use quilkin::test_utils::{ephemeral_socket, logger, recv_socket_done};
    use tokio::time::{delay_for, Duration};

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

        let (close_server, stop_server) = oneshot::channel::<()>();
        let server = Server::new(base_logger.clone(), default_filters(&base_logger));
        // run the server
        tokio::spawn(async move {
            server
                .run(Arc::new(server_config), stop_server)
                .await
                .unwrap();
        });

        // create a local client
        let client_port = 12344;
        let client_config = Config {
            local: Local { port: client_port },
            filters: vec![],
            connections: ConnectionConfig::Client {
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port),
                connection_id: String::from(""),
            },
        };
        let client = Server::new(base_logger.clone(), default_filters(&base_logger));
        let (close_client, stop_client) = oneshot::channel::<()>();
        // run the client
        tokio::spawn(async move {
            client
                .run(Arc::new(client_config), stop_client)
                .await
                .unwrap();
        });

        // let's send the packet
        let (mut send_chan, mut recv_chan) = mpsc::channel::<String>(10);
        let (mut recv, mut send) = ephemeral_socket().await.split();
        // a channel, so we can wait for packets coming back.
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            loop {
                let (size, _) = recv.recv_from(&mut buf).await.unwrap();
                let str = from_utf8(&buf[..size]).unwrap().to_string();
                send_chan.send(str).await.unwrap();
            }
        });

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
        close_server.send(()).unwrap();
        close_client.send(()).unwrap();
    }

    #[tokio::test]
    // gate to make sure our test functions do what we expect.
    async fn test_echo_server() {
        let echo_addr = echo_server().await;
        let (recv, mut send) = ephemeral_socket().await.split();
        let (done, wait) = oneshot::channel::<()>();
        recv_socket_done(recv, done);
        send.send_to("hello".as_bytes(), &echo_addr).await.unwrap();
        wait.await.unwrap();
    }

    async fn echo_server() -> SocketAddr {
        let mut socket = ephemeral_socket().await;
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let (size, sender) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&buf[..size], sender).await.unwrap();
        });
        addr
    }
}
