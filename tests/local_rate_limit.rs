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

use tokio::time::{timeout, Duration};

use quilkin::{config::Filter, endpoint::EndpointAddress, filters::local_rate_limit};

#[tokio::test]
async fn local_rate_limit_filter() {
    const PACKET: &[u8] = b"hello";
    const UNSPECIFIED: (std::net::Ipv4Addr, u16) = (std::net::Ipv4Addr::LOCALHOST, 0);
    let client = tokio::net::UdpSocket::bind(UNSPECIFIED).await.unwrap();
    let server = tokio::net::UdpSocket::bind(UNSPECIFIED).await.unwrap();

    let server_addr = EndpointAddress::from(server.local_addr().unwrap());
    let yaml = "
max_packets: 2
period: 1
";

    let quilkin = quilkin::Socket::bind(
        UNSPECIFIED,
        &[Filter {
            name: local_rate_limit::NAME.into(),
            config: Some(serde_yaml::from_str(yaml).unwrap()),
        }],
    )
    .await
    .unwrap();
    quilkin.set_static_upstream(vec![server_addr.clone().into()]);
    tokio::spawn(quilkin.clone().process_worker());

    for _ in 0..3 {
        client
            .send_to(
                PACKET,
                quilkin.local_addr().unwrap().to_socket_addr().unwrap(),
            )
            .await
            .unwrap();
    }

    async fn recv(socket: &tokio::net::UdpSocket) -> Vec<u8> {
        let mut buf = vec![0; u16::MAX as usize];
        let (length, _) = socket.recv_from(&mut buf).await.unwrap();
        buf[..length].into()
    }

    for _ in 0..2 {
        assert_eq!(PACKET, recv(&server).await);
    }

    // Allow enough time to have received any response.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Check that we do not get any response.
    assert!(timeout(Duration::from_millis(500), recv(&server))
        .await
        .is_err());
}
