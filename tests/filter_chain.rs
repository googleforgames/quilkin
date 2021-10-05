/*
 * Copyright 2021 Google LLC
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

use quilkin::test_utils::{wait_for, wait_for_ok, TestHelper};

#[tokio::test]
async fn static_versioned_filter_chains() {
    let mut t = TestHelper::default();

    // create an echo server as a server.
    let server_address = t.run_echo_server().await;

    let proxy_port = "12348";
    let yaml = format!(
        "
version: v1alpha1
proxy:
  id: test-versioned-filter-chain
  port: {}
static:
  filter_chain:
    versioned:
      capture_version:
        strategy: PREFIX
        size: 1
      filter_chains:
      - versions:
        - AA==
        - AQ==
        filters:
        - name: quilkin.extensions.filters.concatenate_bytes.v1alpha1.ConcatenateBytes
          config:
            on_read: APPEND
            on_write: DO_NOTHING
            bytes: ZmlsdGVyLTE=
      - versions:
        - Ag==
        filters:
        - name: quilkin.extensions.filters.concatenate_bytes.v1alpha1.ConcatenateBytes
          config:
            on_read: APPEND
            on_write: DO_NOTHING
            bytes: ZmlsdGVyLTI=
  endpoints:
  - address: {}
",
        proxy_port, server_address
    );

    t.run_server_with_config(serde_yaml::from_str(yaml.as_str()).unwrap());

    let tests = vec![
        // (version, expected_response_packet)
        (vec![0], "hello-filter-1".to_string()),
        (vec![1], "hello-filter-1".to_string()),
        (vec![2], "hello-filter-2".to_string()),
    ];

    // Test that for each version we get the expected filter chain transformation.
    for (version, expected) in tests {
        // Create a new client each time since we can't use different versions for
        // the same client.
        let (mut client_packet_rx, client_socket) = t.open_socket_and_recv_multiple_packets().await;
        client_socket
            .connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        // Use the client to send the packet to Quilkin.
        let packet: Vec<u8> = vec![version.clone(), String::from("hello-").into_bytes()].concat();
        wait_for_ok(client_socket.send(&packet)).await.unwrap();

        // Wait for the client to receive a response back.
        let response = wait_for(client_packet_rx.recv()).await.unwrap();

        assert_eq!(Some(expected), response);
    }
}
