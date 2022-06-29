/*
 * Copyright 2022 Google LLC
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

use std::{
    collections::BTreeMap,
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use k8s_openapi::{api::core::v1::Namespace, apimachinery::pkg::apis::meta::v1::ObjectMeta};
use kube::{
    api::{DeleteParams, ListParams, PostParams},
    Api, ResourceExt,
};
use tokio::sync::OnceCell;

mod pod;

#[allow(dead_code)]
static CLIENT: OnceCell<Client> = OnceCell::const_new();
#[allow(dead_code)]
const QUILKIN_IMAGE: &str = "QUILKIN_IMAGE";

pub struct Client {
    /// The Kubernetes client
    pub kubernetes: kube::Client,
    /// The namespace the tests will happen in
    pub namespace: String,
    /// The name and tag of the Quilkin image being tested
    pub quilkin_image: String,
}

impl Client {
    /// Thread safe way to create a Client once and only once across multiple tests.
    /// Executes the setup required:
    /// * Creates a test namespace for this test
    /// * Removes previous test namespaces
    /// * Retrieves the QUILKIN_IMAGE to test from env vars, and defaults it if not available.
    pub async fn new() -> &'static Client {
        CLIENT
            .get_or_init(|| async {
                let client = kube::Client::try_default()
                    .await
                    .expect("Kubernetes client to be created");

                Client {
                    kubernetes: client.clone(),
                    namespace: setup_namespace(client).await,
                    quilkin_image: env::var_os(QUILKIN_IMAGE)
                        .unwrap_or_else(|| "us-docker.pkg.dev/quilkin/release/quilkin:0.3.0".into())
                        .into_string()
                        .unwrap(),
                }
            })
            .await
    }
}

/// Deletes old quilkin test namespaces, and then create
/// a new namespace based on EPOCH time, and return its string value.
#[allow(dead_code)]
async fn setup_namespace(client: kube::Client) -> String {
    let namespaces: Api<Namespace> = Api::all(client.clone());

    let lp = ListParams::default().labels("owner=quilkin-test");
    let nss = namespaces.list(&lp).await.unwrap();
    let dp = DeleteParams::default();
    for ns in nss {
        let name = ns.name();
        if let Err(err) = namespaces.delete(name.as_str(), &dp).await {
            println!("Failure attempting to deleted namespace: {:?}, {err}", name);
        }
    }

    let name = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let metadata = ObjectMeta {
        name: Some(name),
        labels: Some(BTreeMap::from([("owner".into(), "quilkin-test".into())])),
        ..Default::default()
    };
    let test_namespace = Namespace {
        metadata,
        spec: None,
        status: None,
    };

    let pp = PostParams::default();
    namespaces
        .create(&pp, &test_namespace)
        .await
        .expect("namespace to be created");

    test_namespace.name()
}
