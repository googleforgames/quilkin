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
use std::panic;

use hyper::{Client, Uri};

use quilkin::{config::Admin, endpoint::Endpoint, test_utils::TestHelper};

const LIVE_ADDRESS: &str = "http://localhost:9093/live";

#[tokio::test]
async fn health_server() {
    let mut t = TestHelper::default();

    // create server configuration
    let server_port = 12349;
    let server_config = quilkin::Server::builder()
        .port(server_port)
        .endpoints(vec!["127.0.0.1:0".parse::<Endpoint>().unwrap()])
        .admin(Admin {
            address: "[::]:9093".parse().unwrap(),
        })
        .build()
        .unwrap();
    t.run_server(<_>::try_from(server_config).unwrap());

    let client = Client::new();
    let resp = client
        .get(Uri::from_static(LIVE_ADDRESS))
        .await
        .map(|resp| resp.into_body())
        .map(hyper::body::to_bytes)
        .unwrap()
        .await
        .unwrap();

    assert_eq!("ok", String::from_utf8(resp.to_vec()).unwrap());

    let _ = panic::catch_unwind(|| {
        panic!("oh no!");
    });

    let resp = client.get(Uri::from_static(LIVE_ADDRESS)).await.unwrap();
    assert!(resp.status().is_server_error(), "Should be unhealthy");
}
