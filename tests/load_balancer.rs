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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

use quilkin::{
    config::Filter,
    endpoint::Endpoint,
    filters::{LoadBalancer, StaticFilter},
    test_utils::TestHelper,
};

#[tokio::test]
async fn load_balancer_filter() {
    let mut t = TestHelper::default();

    let yaml = "
policy: ROUND_ROBIN
";
    let selected_endpoint = Arc::new(Mutex::new(None::<SocketAddr>));

    let mut echo_addresses = vec![];
    for _ in 0..2 {
        let selected_endpoint = selected_endpoint.clone();
        echo_addresses.push(
            t.run_echo_server_with_tap(move |_, _, echo_addr| {
                let _ = selected_endpoint.lock().unwrap().replace(echo_addr);
            })
            .await,
        )
    }

    let server_port = 12346;
    let server_config = quilkin::Server::builder()
        .port(server_port)
        .filters(vec![Filter {
            name: LoadBalancer::factory().name().into(),
            config: serde_yaml::from_str(yaml).unwrap(),
        }])
        .endpoints(echo_addresses.iter().cloned().map(Endpoint::new).collect())
        .build()
        .unwrap();
    t.run_server_with_config(server_config);
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);

    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    for addr in echo_addresses {
        socket.send_to(b"hello", &server_addr).await.unwrap();
        let value = timeout(Duration::from_secs(5), recv_chan.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!("hello", value);

        assert_eq!(
            addr,
            selected_endpoint.lock().unwrap().take().unwrap().into()
        );
    }
}
