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
use std::{panic, sync::Arc};

use quilkin::{
    config::{Admin, Builder},
    endpoint::Endpoint,
    test_utils::TestHelper,
    Builder as ProxyBuilder,
};

#[tokio::test]
async fn health_server() {
    let mut t = TestHelper::default();

    // create server configuration
    let server_port = 12349;
    let server_config = Builder::empty()
        .with_port(server_port)
        .with_static(vec![], vec![Endpoint::new("127.0.0.1:0".parse().unwrap())])
        .with_admin(Admin {
            address: "[::]:9093".parse().unwrap(),
        })
        .build();
    t.run_server_with_builder(ProxyBuilder::from(Arc::new(server_config)));

    let resp = reqwest::get("http://localhost:9093/live")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!("ok", resp);

    let _ = panic::catch_unwind(|| {
        panic!("oh no!");
    });

    let resp = reqwest::get("http://localhost:9093/live").await.unwrap();
    assert!(resp.status().is_server_error(), "Should be unhealthy");
}
