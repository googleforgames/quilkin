/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use tokio::time::{timeout, Duration};

use quilkin::{config::Filter, endpoint::EndpointAddress, filters::firewall};

#[tokio::test]
async fn firewall_allow() {
    let yaml = "
on_read:
  - action: ALLOW
    source: 127.0.0.1/32
    ports:
       - %1
on_write:
  - action: ALLOW
    source: 127.0.0.0/24
    ports:
       - %2
";
    let result = test(yaml).await.unwrap();
    assert_eq!(b"hello", result.as_slice());
}

#[tokio::test]
async fn firewall_read_deny() {
    let yaml = "
on_read:
  - action: DENY
    source: 127.0.0.1/32
    ports:
       - %1
on_write:
  - action: ALLOW
    source: 127.0.0.0/24
    ports:
       - %2
";

    let result = timeout(Duration::from_secs(1), test(yaml)).await;
    assert!(result.is_err(), "should not have received a packet");
}

#[tokio::test]
async fn firewall_write_deny() {
    let yaml = "
on_read:
  - action: ALLOW
    source: 127.0.0.1/32
    ports:
       - %1
on_write:
  - action: DENY
    source: 127.0.0.0/24
    ports:
       - %2
";
    let result = timeout(Duration::from_secs(1), test(yaml)).await;
    assert!(result.is_err(), "should not have received a packet");
}

async fn test(yaml: &str) -> quilkin::Result<Vec<u8>> {
    const PACKET: &[u8] = b"hello";
    const UNSPECIFIED: (std::net::Ipv4Addr, u16) = (std::net::Ipv4Addr::LOCALHOST, 0);
    let client = tokio::net::UdpSocket::bind(UNSPECIFIED).await.unwrap();
    let server = tokio::net::UdpSocket::bind(UNSPECIFIED).await.unwrap();

    let server_addr = EndpointAddress::from(server.local_addr().unwrap());
    let client_addr = EndpointAddress::from(client.local_addr().unwrap());

    let yaml = yaml
        .replace("%1", client_addr.port().to_string().as_str())
        .replace("%2", server_addr.port().to_string().as_str());
    let quilkin = quilkin::Socket::bind(
        UNSPECIFIED,
        &[Filter {
            name: firewall::factory().name().into(),
            config: serde_yaml::from_str(yaml.as_str()).unwrap(),
        }],
    )
    .await
    .unwrap();
    let quilkin_addr = EndpointAddress::from(quilkin.local_addr().unwrap());
    client
        .send_to(PACKET, quilkin_addr.clone().to_socket_addr().unwrap())
        .await
        .unwrap();
    let (response, addr) = quilkin
        .receive_downstream(vec![
            EndpointAddress::from(server.local_addr().unwrap()).into()
        ])
        .await
        .unwrap();
    assert_eq!(PACKET, &response.contents);
    quilkin
        .send_upstream(&response.contents, server_addr, addr)
        .await
        .unwrap();

    let (contents, addr) = {
        let mut buf = vec![0; u16::MAX as usize];
        let (length, addr) = server.recv_from(&mut buf).await.unwrap();
        (Vec::from(&buf[..length]), addr)
    };

    assert_eq!(PACKET, contents);
    server.send_to(&contents, addr).await.unwrap();
    let (contents, upstream, downstream) =
        quilkin.receive_upstream().await.unwrap().next().unwrap();
    assert_eq!(PACKET, &contents);
    quilkin
        .send_downstream(
            contents,
            upstream.to_socket_addr().unwrap(),
            downstream.to_socket_addr().unwrap(),
        )
        .await
        .unwrap();

    let contents = {
        let mut buf = vec![0; u16::MAX as usize];
        let (length, _) = client.recv_from(&mut buf).await.unwrap();
        Vec::from(&buf[..length])
    };

    Ok(contents)
}
