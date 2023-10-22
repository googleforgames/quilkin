/*
 * Copyright 2023 Google LLC
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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tokio::time::Duration;

use quilkin::{
    codec::qcmp::Protocol,
    test::{AddressType, TestHelper},
};

#[tokio::test]
async fn proxy_ping() {
    let mut t = TestHelper::default();
    let server_port = quilkin::test::available_addr(&AddressType::Random)
        .await
        .port();
    let server_proxy = quilkin::cli::Proxy {
        qcmp_port: server_port,
        to: vec![(Ipv4Addr::UNSPECIFIED, 0).into()],
        ..<_>::default()
    };
    let server_config = std::sync::Arc::new(quilkin::Config::default());
    t.run_server(server_config, server_proxy, None);
    ping(server_port).await;
}

#[tokio::test]
async fn agent_ping() {
    let qcmp_port = quilkin::test::available_addr(&AddressType::Random)
        .await
        .port();
    let agent = quilkin::cli::Agent {
        qcmp_port,
        ..<_>::default()
    };
    let server_config = std::sync::Arc::new(quilkin::Config::default());
    let (_tx, rx) = tokio::sync::watch::channel(());
    let admin = quilkin::cli::Admin::Agent(<_>::default());
    tokio::spawn(async move {
        agent
            .run(server_config, admin, rx)
            .await
            .expect("Agent should run")
    });
    ping(qcmp_port).await;
}

async fn ping(port: u16) {
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .unwrap();
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let ping = Protocol::ping();

    tracing::trace!(dest=%local_addr, "sending ping");
    socket.send_to(&ping.encode(), &local_addr).await.unwrap();
    let mut buf = [0; u16::MAX as usize];
    let (size, _) = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let recv_time = chrono::Utc::now().timestamp_nanos_opt().unwrap();
    let reply = Protocol::parse(&buf[..size]).unwrap().unwrap();

    assert_eq!(ping.nonce(), reply.nonce());
    const FIFTY_MILLIS_IN_NANOS: i64 = 50_000_000;

    // If it takes longer than 50 milliseconds locally, it's likely that there
    // is bug.
    let delay = reply.round_trip_delay(recv_time).unwrap();
    assert!(
        FIFTY_MILLIS_IN_NANOS > delay,
        "Delay {}ns greater than {}ns",
        delay,
        FIFTY_MILLIS_IN_NANOS
    );
}
