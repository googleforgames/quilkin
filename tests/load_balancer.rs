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

use std::net::Ipv4Addr;

use tokio::net::UdpSocket;

use quilkin::{
    config::Filter,
    endpoint::{Endpoint, EndpointAddress},
    filters::load_balancer,
};

#[tokio::test]
async fn load_balancer_filter() -> quilkin::Result<()> {
    const UNSPECIFIED: (Ipv4Addr, u16) = (Ipv4Addr::UNSPECIFIED, 0);
    let cluster = vec![
        UdpSocket::bind(UNSPECIFIED).await?,
        UdpSocket::bind(UNSPECIFIED).await?,
        UdpSocket::bind(UNSPECIFIED).await?,
        UdpSocket::bind(UNSPECIFIED).await?,
        UdpSocket::bind(UNSPECIFIED).await?,
    ];

    let client = UdpSocket::bind(UNSPECIFIED).await?;

    let quilkin = quilkin::Socket::bind(
        UNSPECIFIED,
        &[Filter {
            name: load_balancer::NAME.into(),
            config: Some(
                serde_yaml::to_value(&load_balancer::Config::new(
                    load_balancer::Policy::RoundRobin,
                ))
                .map(From::from)?,
            ),
        }],
    )
    .await?;

    let endpoints = cluster
        .iter()
        .filter_map(|s| s.local_addr().ok())
        .map(EndpointAddress::from)
        .map(Endpoint::from)
        .collect();

    quilkin.set_static_upstream(endpoints);
    tokio::spawn(quilkin.clone().process_worker());

    let quilkin_addr = quilkin.local_addr()?;
    for (i, _) in cluster.iter().enumerate() {
        client
            .send_to(&[i as u8], quilkin_addr.clone().to_socket_addr()?)
            .await?;
    }

    for (i, endpoint) in cluster.iter().enumerate() {
        let mut buf = vec![0; u16::MAX as usize];
        let (length, _) = endpoint.recv_from(&mut buf).await?;
        assert_eq!(&[i as u8], &buf[..length]);
    }

    Ok(())
}
