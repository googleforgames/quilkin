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

use std::time::Duration;

use tokio::time::timeout;

use quilkin::{
    config::Filter,
    endpoint::Endpoint,
    filters::{LocalRateLimit, StaticFilter},
    test_utils::{available_addr, TestHelper},
};

#[tokio::test]
async fn local_rate_limit_filter() {
    let mut t = TestHelper::default();

    let yaml = "
max_packets: 2
period: 1
";
    let echo = t.run_echo_server().await;

    let server_addr = available_addr().await;
    let server_config = quilkin::Config::builder()
        .port(server_addr.port())
        .filters(vec![Filter {
            name: LocalRateLimit::factory().name().into(),
            config: serde_yaml::from_str(yaml).unwrap(),
        }])
        .endpoints(vec![Endpoint::new(echo)])
        .build()
        .unwrap();
    t.run_server_with_config(server_config);

    let msg = "hello";
    let (mut rx, socket) = t.open_socket_and_recv_multiple_packets().await;

    for _ in 0..3 {
        socket.send_to(msg.as_bytes(), &server_addr).await.unwrap();
    }

    for _ in 0..2 {
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap()
        );
    }

    // Allow enough time to have received any response.
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Check that we do not get any response.
    assert!(timeout(Duration::from_secs(1), rx.recv()).await.is_err());
}
