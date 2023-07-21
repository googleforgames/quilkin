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

use std::net::{Ipv6Addr, SocketAddr};

use tokio::{
    sync::oneshot,
    time::{timeout, Duration},
};

use quilkin::{
    config::Filter,
    endpoint::Endpoint,
    filters::{Firewall, StaticFilter},
    test_utils::{available_addr, AddressType, TestHelper},
};

#[tokio::test]
async fn ipv4_firewall_allow() {
    let mut t = TestHelper::default();
    let address_type = AddressType::Ipv4;
    let port = available_addr(&address_type).await.port();
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
    let recv = test(&mut t, port, yaml, &address_type).await;

    assert_eq!(
        "hello",
        timeout(Duration::from_secs(5), recv)
            .await
            .expect("should have received a packet")
            .unwrap()
    );
}

#[tokio::test]
async fn ipv6_firewall_allow() {
    let mut t = TestHelper::default();
    let address_type = AddressType::Ipv6;
    let port = available_addr(&address_type).await.port();
    let yaml = "
on_read:
  - action: ALLOW
    source: ::1/128
    ports:
       - %1
on_write:
  - action: ALLOW
    source: ::1/64
    ports:
       - %2
";
    let recv = test(&mut t, port, yaml, &address_type).await;

    assert_eq!(
        "hello",
        timeout(Duration::from_secs(5), recv)
            .await
            .expect("should have received a packet")
            .unwrap()
    );
}

#[tokio::test]
async fn ipv4_firewall_read_deny() {
    let mut t = TestHelper::default();
    let address_type = AddressType::Ipv4;
    let port = available_addr(&address_type).await.port();
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
    let recv = test(&mut t, port, yaml, &address_type).await;

    let result = timeout(Duration::from_secs(3), recv).await;
    assert!(result.is_err(), "should not have received a packet");
}

#[tokio::test]
async fn ipv6_firewall_read_deny() {
    let mut t = TestHelper::default();
    let address_type = AddressType::Ipv6;
    let port = available_addr(&address_type).await.port();
    let yaml = "
on_read:
  - action: DENY
    source: ::1/128
    ports:
       - %1
on_write:
  - action: ALLOW
    source: ::1/64
    ports:
       - %2
";
    let recv = test(&mut t, port, yaml, &address_type).await;

    let result = timeout(Duration::from_secs(3), recv).await;
    assert!(result.is_err(), "should not have received a packet");
}

#[tokio::test]
async fn ipv4_firewall_write_deny() {
    let mut t = TestHelper::default();
    let address_type = AddressType::Ipv4;
    let port = available_addr(&address_type).await.port();
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
    let recv = test(&mut t, port, yaml, &address_type).await;

    let result = timeout(Duration::from_secs(3), recv).await;
    assert!(result.is_err(), "should not have received a packet");
}

#[tokio::test]
async fn ipv6_firewall_write_deny() {
    let mut t = TestHelper::default();
    let address_type = AddressType::Ipv6;
    let port = available_addr(&address_type).await.port();
    let yaml = "
on_read:
  - action: ALLOW
    source: ::1/128
    ports:
       - %1
on_write:
  - action: DENY
    source: ::1/64
    ports:
       - %2
";
    let recv = test(&mut t, port, yaml, &address_type).await;

    let result = timeout(Duration::from_secs(3), recv).await;
    assert!(result.is_err(), "should not have received a packet");
}

async fn test(
    t: &mut TestHelper,
    server_port: u16,
    yaml: &str,
    address_type: &AddressType,
) -> oneshot::Receiver<String> {
    let echo = t.run_echo_server(address_type).await;

    let recv = t.open_socket_and_recv_single_packet().await;
    let client_addr = match address_type {
        AddressType::Ipv4 => recv.socket.local_ipv4_addr().unwrap(),
        AddressType::Ipv6 => recv.socket.local_ipv6_addr().unwrap(),
        AddressType::Random => unreachable!(),
    };

    let yaml = yaml
        .replace("%1", client_addr.port().to_string().as_str())
        .replace("%2", echo.port().to_string().as_str());
    tracing::info!(config = yaml.as_str(), "Config");

    let server_proxy = quilkin::cli::Proxy {
        port: server_port,
        ..<_>::default()
    };
    let server_config = std::sync::Arc::new(quilkin::Config::default());
    server_config.filters.store(
        quilkin::filters::FilterChain::try_from(vec![Filter {
            name: Firewall::factory().name().into(),
            label: None,
            config: serde_yaml::from_str(yaml.as_str()).unwrap(),
        }])
        .map(std::sync::Arc::new)
        .unwrap(),
    );

    server_config
        .clusters
        .modify(|clusters| clusters.insert_default(vec![Endpoint::new(echo.clone())]));

    t.run_server(server_config, server_proxy, None);

    let local_addr: SocketAddr = match address_type {
        AddressType::Ipv4 => (std::net::Ipv4Addr::LOCALHOST, server_port).into(),
        AddressType::Ipv6 => (Ipv6Addr::LOCALHOST, server_port).into(),
        AddressType::Random => unreachable!(), // don't do this.
    };
    tracing::info!(source = %client_addr, address = %local_addr, "Sending hello");
    recv.socket.send_to(b"hello", &local_addr).await.unwrap();

    recv.packet_rx
}
