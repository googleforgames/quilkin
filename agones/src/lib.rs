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

use k8s_openapi::{
    api::{
        apps::v1::Deployment,
        core::v1::{
            ConfigMap, Container, EnvVar, HTTPGetAction, Namespace, Pod, PodSpec, PodTemplateSpec,
            Probe, ResourceRequirements, ServiceAccount, VolumeMount,
        },
        rbac::v1::{RoleBinding, RoleRef, Subject},
    },
    apimachinery::pkg::{
        api::resource::Quantity, apis::meta::v1::ObjectMeta, util::intstr::IntOrString,
    },
    chrono,
};
use kube::{
    api::{DeleteParams, ListParams, PostParams},
    runtime::wait::Condition,
    Api, Resource, ResourceExt,
};
use tokio::sync::OnceCell;

use quilkin::config::watch::agones::crd::{
    Fleet, FleetSpec, GameServer, GameServerPort, GameServerSpec, GameServerState,
    GameServerTemplateSpec,
};

mod pod;
mod sidecar;
mod xds;

#[allow(dead_code)]
static CLIENT: OnceCell<Client> = OnceCell::const_new();
#[allow(dead_code)]
const IMAGE_TAG: &str = "IMAGE_TAG";
const DELETE_DELAY_SECONDS: &str = "DELETE_DELAY_SECONDS";
/// A simple udp server that returns packets that are sent to it.
/// See: <https://github.com/googleforgames/agones/tree/main/examples/simple-game-server>
/// for more details.
pub const GAMESERVER_IMAGE: &str = "gcr.io/agones-images/simple-game-server:0.13";

#[derive(Clone)]
pub struct Client {
    /// The Kubernetes client
    pub kubernetes: kube::Client,
    /// The namespace the tests will happen in
    pub namespace: String,
    /// The name and tag of the Quilkin image being tested
    pub quilkin_image: String,
}

impl Client {
    /// Thread safe way to create a Clients across multiple tests.
    /// Executes the setup required:
    /// * Creates a test namespace for this test
    /// * Removes previous test namespaces
    /// * Retrieves the IMAGE_TAG to test from env vars, and panics if it if not available.
    pub async fn new() -> Client {
        let mut client = CLIENT
            .get_or_init(|| async {
                let client = kube::Client::try_default()
                    .await
                    .expect("Kubernetes client to be created");

                Client {
                    kubernetes: client.clone(),
                    namespace: setup_namespace(client).await,
                    quilkin_image: env::var(IMAGE_TAG).unwrap(),
                }
            })
            .await
            .clone();

        // create a new client on each invocation, as the client can close
        // at the end of each test.
        client.kubernetes = kube::Client::try_default()
            .await
            .expect("Kubernetes client to be created");
        client
    }

    /// Returns a typed API client for this client in this test namespace.
    pub fn namespaced_api<K: Resource>(&self) -> Api<K>
    where
        <K as Resource>::DynamicType: Default,
    {
        Api::namespaced(self.kubernetes.clone(), self.namespace.as_str())
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

    let delay = env::var(DELETE_DELAY_SECONDS)
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .map(chrono::Duration::seconds);

    for ns in nss {
        let name = ns.name();

        let delete = delay
            .and_then(|duration| {
                let expiry = ns.creation_timestamp()?.0 + duration;
                Some(chrono::Utc::now() > expiry)
            })
            .unwrap_or(true);
        if delete {
            if let Err(err) = namespaces.delete(name.as_str(), &dp).await {
                println!("Failure attempting to deleted namespace: {:?}, {err}", name);
            }
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

    add_agones_service_account(client, test_namespace.name()).await;

    test_namespace.name()
}

async fn add_agones_service_account(client: kube::Client, namespace: String) {
    let service_accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace.as_str());
    let role_bindings: Api<RoleBinding> = Api::namespaced(client, namespace.as_str());
    let pp = PostParams::default();
    let labels = BTreeMap::from([("app".to_string(), "agones".to_string())]);

    let service_account = ServiceAccount {
        metadata: ObjectMeta {
            name: Some("agones-sdk".into()),
            namespace: Some(namespace.clone()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        ..Default::default()
    };

    let service_account = service_accounts
        .create(&pp, &service_account)
        .await
        .unwrap();

    let role_binding = RoleBinding {
        metadata: ObjectMeta {
            name: Some("agones-sdk-access".into()),
            namespace: Some(namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".into(),
            kind: "ClusterRole".into(),
            name: "agones-sdk".into(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".into(),
            name: service_account.name(),
            namespace: Some(namespace),
            api_group: None,
        }]),
    };

    let _ = role_bindings.create(&pp, &role_binding).await.unwrap();
}

/// Returns a test GameServer with the UDP test binary that is used for
/// Agones e2e tests.
pub fn game_server() -> GameServer {
    let mut resources = BTreeMap::new();

    resources.insert("cpu".into(), Quantity("30m".into()));
    resources.insert("memory".into(), Quantity("32Mi".into()));

    GameServer {
        metadata: ObjectMeta {
            generate_name: Some("gameserver-".into()),
            ..Default::default()
        },
        spec: GameServerSpec {
            ports: vec![GameServerPort {
                container_port: 7654,
                host_port: None,
                name: "udp-port".into(),
                port_policy: Default::default(),
                container: None,
                protocol: Default::default(),
            }],
            template: PodTemplateSpec {
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "game-server".into(),
                        image: Some(GAMESERVER_IMAGE.into()),
                        resources: Some(ResourceRequirements {
                            limits: Some(resources.clone()),
                            requests: Some(resources),
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        },
        status: None,
    }
}

/// Returns a Fleet of 3 replicas of the UDP testing GameServer
pub fn fleet() -> Fleet {
    let gs = game_server();
    Fleet {
        metadata: ObjectMeta {
            generate_name: Some("fleet-".into()),
            ..Default::default()
        },
        spec: FleetSpec {
            replicas: Some(3),
            template: GameServerTemplateSpec {
                metadata: None,
                spec: gs.spec,
            },
            ..Default::default()
        },
        status: None,
    }
}

/// Condition to wait for a GameServer to become Ready.
pub fn is_gameserver_ready() -> impl Condition<GameServer> {
    |obj: Option<&GameServer>| {
        obj.and_then(|gs| gs.status.clone())
            .map(|status| matches!(status.state, GameServerState::Ready))
            .unwrap_or(false)
    }
}

pub fn is_pod_ready() -> impl Condition<Pod> {
    |obj: Option<&Pod>| {
        if let Some(pod) = obj {
            return pod
                .status
                .as_ref()
                .and_then(|status| status.conditions.as_ref())
                .and_then(|conditions| {
                    conditions
                        .iter()
                        .find(|condition| condition.type_ == "Ready" && condition.status == "True")
                })
                .is_some();
        }
        false
    }
}

/// Condition to wait for a Deployment to have all the replicas it is expecting to be ready.
pub fn is_deployment_ready() -> impl Condition<Deployment> {
    |obj: Option<&Deployment>| {
        if let Some(deployment) = obj {
            let expected = deployment.spec.as_ref().unwrap().replicas.as_ref().unwrap();

            return deployment
                .status
                .as_ref()
                .and_then(|status| status.ready_replicas)
                .map(|replicas| &replicas == expected)
                .unwrap_or(false);
        }
        false
    }
}

/// Condition to wait for a Fleet to have all the replicas it is expecting to be ready.
pub fn is_fleet_ready() -> impl Condition<Fleet> {
    |obj: Option<&Fleet>| {
        if let Some(fleet) = obj {
            let expected = fleet.spec.replicas.as_ref().unwrap();

            return fleet
                .status
                .as_ref()
                .and_then(|status| status.ready_replicas)
                .map(|replicas| &replicas == expected)
                .unwrap_or(false);
        }
        false
    }
}

/// Returns a container for Quilkin, with an optional volume mount name
pub fn quilkin_container(
    client: &Client,
    args: Option<Vec<String>>,
    volume_mount: Option<String>,
) -> Container {
    let mut container = Container {
        name: "quilkin".into(),
        image: Some(client.quilkin_image.clone()),
        args,
        env: Some(vec![EnvVar {
            name: "RUST_LOG".to_string(),
            value: Some("quilkin=trace".into()),
            value_from: None,
        }]),
        liveness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/live".into()),
                port: IntOrString::Int(9091),
                ..Default::default()
            }),
            initial_delay_seconds: Some(3),
            period_seconds: Some(2),
            ..Default::default()
        }),
        readiness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/ready".into()),
                port: IntOrString::Int(9091),
                ..Default::default()
            }),
            initial_delay_seconds: Some(3),
            period_seconds: Some(2),
            ..Default::default()
        }),
        ..Default::default()
    };

    if let Some(name) = volume_mount {
        container.volume_mounts = Some(vec![VolumeMount {
            name,
            mount_path: "/etc/quilkin".into(),
            ..Default::default()
        }])
    };

    container
}

/// Return a ConfigMap in the format that Quilkin expects it to be able to
/// consume the config yaml.
pub fn quilkin_config_map(config: &str) -> ConfigMap {
    ConfigMap {
        metadata: ObjectMeta {
            generate_name: Some("quilkin-config-".into()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([(
            "quilkin.yaml".to_string(),
            config.to_string(),
        )])),
        ..Default::default()
    }
}

/// Convenience function to return the address with the first port of GameServer
pub fn gameserver_address(gs: &GameServer) -> String {
    let status = gs.status.as_ref().unwrap();
    let address = format!(
        "{}:{}",
        status.address,
        status.ports.as_ref().unwrap()[0].port
    );
    address
}
