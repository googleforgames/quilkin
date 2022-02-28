/*
 * Copyright 2020 Google LLC
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

use tokio::time::{timeout, Duration};

use quilkin::{
    config::Filter,
    filters::{capture, r#match},
};

#[tokio::test]
async fn r#match() {
    let capture_yaml = "
suffix:
    size: 3
    remove: true
";

    let matches_yaml = "
on_read:
    metadataKey: quilkin.dev/capture
    fallthrough:
        id: quilkin.filters.concatenate_bytes.v1alpha1.ConcatenateBytes
        config:
            on_read: APPEND
            bytes: ZGVm
    branches:
        - value: abc
          id: quilkin.filters.concatenate_bytes.v1alpha1.ConcatenateBytes
          config:
            on_read: APPEND
            bytes: eHl6 # xyz
        - value: xyz
          id: quilkin.filters.concatenate_bytes.v1alpha1.ConcatenateBytes
          config:
            on_read: APPEND
            bytes: YWJj # abc
";
    const UNSPECIFIED: (std::net::Ipv4Addr, u16) = (std::net::Ipv4Addr::LOCALHOST, 0);
    let client = std::sync::Arc::new(tokio::net::UdpSocket::bind(UNSPECIFIED).await.unwrap());
    let server = tokio::net::UdpSocket::bind(UNSPECIFIED).await.unwrap();

    let server_addr = quilkin::endpoint::EndpointAddress::from(server.local_addr().unwrap());
    let quilkin = quilkin::Socket::bind(
        UNSPECIFIED,
        &[
            Filter {
                name: capture::NAME.into(),
                config: serde_yaml::from_str(capture_yaml).unwrap(),
            },
            Filter {
                name: r#match::NAME.into(),
                config: serde_yaml::from_str(matches_yaml).unwrap(),
            },
        ],
    )
    .await
    .unwrap();

    quilkin.set_static_upstream(vec![server_addr.into()]);
    tokio::spawn(quilkin.clone().process_worker());
    let quilkin_addr = quilkin.local_addr().unwrap();
    let client_send = |msg| {
        let client = client.clone();
        let quilkin_addr = quilkin_addr.clone();
        async move {
            client
                .send_to(msg, quilkin_addr.to_socket_addr().unwrap())
                .await
                .unwrap();
        }
    };

    let response = || async {
        let mut buf = vec![0; u16::MAX as usize];
        let (length, _) = server.recv_from(&mut buf).await.unwrap();
        buf[..length].to_owned()
    };

    // abc packet
    let msg = b"helloabc";
    (client_send)(msg).await;

    assert_eq!(
        b"helloxyz",
        timeout(Duration::from_secs(5), (response)())
            .await
            .unwrap()
            .as_slice()
    );

    // send an xyz packet
    let msg = b"helloxyz";
    (client_send)(msg).await;

    assert_eq!(
        b"helloabc",
        timeout(Duration::from_secs(5), (response)())
            .await
            .expect("should have received a packet")
            .as_slice()
    );

    // fallthrough packet
    let msg = b"hellodef";
    (client_send)(msg).await;

    assert_eq!(
        b"hellodef",
        timeout(Duration::from_secs(5), (response)())
            .await
            .expect("should have received a packet")
            .as_slice()
    );

    // second fallthrough packet
    let msg = b"hellofgh";
    (client_send)(msg).await;

    assert_eq!(
        b"hellodef",
        timeout(Duration::from_secs(5), (response)())
            .await
            .expect("should have received a packet")
            .as_slice()
    );
}
