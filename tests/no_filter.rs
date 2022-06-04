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

use tokio::time::timeout;
use tokio::time::Duration;

use quilkin::test_utils::available_addr;
use quilkin::{endpoint::Endpoint, test_utils::TestHelper};

#[tokio::test]
async fn echo() {
    let mut t = TestHelper::default();

    // create two echo servers as endpoints
    let server1 = t.run_echo_server().await;
    let server2 = t.run_echo_server().await;

    // create server configuration
    let local_addr = available_addr().await;
    let server_config = quilkin::Server::builder()
        .port(local_addr.port())
        .endpoints(vec![Endpoint::new(server1), Endpoint::new(server2)])
        .build()
        .unwrap();

    t.run_server_with_config(server_config);

    // let's send the packet
    let (mut recv_chan, socket) = t.open_socket_and_recv_multiple_packets().await;

    socket.send_to(b"hello", &local_addr).await.unwrap();
    let value = timeout(Duration::from_secs(5), recv_chan.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!("hello", value);
    let value = timeout(Duration::from_secs(5), recv_chan.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!("hello", value);

    // should only be two returned items
    assert!(timeout(Duration::from_secs(2), recv_chan.recv())
        .await
        .is_err());
}
