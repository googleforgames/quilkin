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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::{collections::BTreeMap, time::Duration};

    use k8s_openapi::{
        api::{
            apps::v1::{Deployment, DeploymentSpec},
            core::v1::{
                ConfigMap, ConfigMapVolumeSource, ContainerPort, Node, Pod, PodSpec,
                PodTemplateSpec, Service, ServiceAccount, ServicePort, ServiceSpec, Volume,
            },
            rbac::v1::{ClusterRole, PolicyRule, RoleBinding, RoleRef, Subject},
        },
        apimachinery::pkg::{
            apis::meta::v1::{LabelSelector, ObjectMeta},
            util::intstr::IntOrString,
        },
    };
    use kube::{
        api::{DeleteParams, ListParams, PostParams},
        runtime::wait::await_condition,
        Api, ResourceExt,
    };
    use tokio::time::timeout;

    use quilkin::{
        config::watch::agones::crd::{Fleet, GameServer},
        test_utils::TestHelper,
    };

    use crate::{
        fleet, is_deployment_ready, is_fleet_ready, quilkin_config_map, quilkin_container, Client,
    };

    const PROXY_DEPLOYMENT: &str = "quilkin-proxies";

    #[tokio::test]
    /// Test for Agones integration. Since this will look at all GameServers in the namespace
    /// for this test, we should only have single Agones integration test in this suite, since they
    /// could easily collide with each other.
    async fn agones_token_router() {
        let client = Client::new().await;

        let deployments: Api<Deployment> = client.namespaced_api();
        let fleets: Api<Fleet> = client.namespaced_api();
        let gameservers: Api<GameServer> = client.namespaced_api();
        let config_maps: Api<ConfigMap> = client.namespaced_api();

        let pp = PostParams::default();

        let config = r#"
version: v1alpha1
filters:
  - name: quilkin.filters.capture.v1alpha1.Capture # Capture and remove the authentication token
    config:
      suffix:
          size: 3
          remove: true
  - name: quilkin.filters.token_router.v1alpha1.TokenRouter
"#;
        let mut config_map = quilkin_config_map(config);
        config_map
            .metadata
            .labels
            .get_or_insert(Default::default())
            .insert("quilkin.dev/configmap".into(), "true".into());

        config_maps.create(&pp, &config_map).await.unwrap();

        agones_control_plane(&client, deployments.clone()).await;
        let proxy_address =
            quilkin_proxy_deployment(&client, config_maps, deployments.clone()).await;

        // create a fleet so we can ensure that a packet is going to the GameServer we expect, and not
        // any other.
        let fleet = fleet();
        let fleet = fleets.create(&pp, &fleet).await.unwrap();
        let name = fleet.name_unchecked();
        timeout(
            Duration::from_secs(30),
            await_condition(fleets.clone(), name.as_str(), is_fleet_ready()),
        )
        .await
        .expect("Fleet should be ready")
        .unwrap();

        let lp = ListParams {
            label_selector: Some(format!("agones.dev/fleet={}", fleet.name_unchecked())),
            ..Default::default()
        };
        let list = gameservers.list(&lp).await.unwrap();

        // let's allocate this specific game server
        let mut t = TestHelper::default();
        let (mut rx, socket) = t.open_socket_and_recv_multiple_packets().await;

        let mut gs = list.items[0].clone();
        let gs_address = crate::gameserver_address(&gs);

        // add routing label to the GameServer
        let token = "456"; // NDU2
        assert_eq!(3, token.as_bytes().len());
        let token_key = "quilkin.dev/tokens";
        gs.metadata
            .annotations
            .get_or_insert(Default::default())
            .insert(token_key.into(), base64::encode(token));
        gameservers
            .replace(gs.name_unchecked().as_str(), &pp, &gs)
            .await
            .unwrap();
        // and allocate it such that we have an endpoint.
        socket
            .send_to("ALLOCATE".as_bytes(), gs_address)
            .await
            .unwrap();

        let response = timeout(Duration::from_secs(30), rx.recv())
            .await
            .expect("should receive packet from GameServer")
            .unwrap();
        assert_eq!("ACK: ALLOCATE\n", response);

        // Proxy Deployment should be ready, since there is now an endpoint
        timeout(
            Duration::from_secs(30),
            await_condition(deployments.clone(), PROXY_DEPLOYMENT, is_deployment_ready()),
        )
        .await
        .expect("Quilkin proxy deployment should be ready")
        .unwrap();

        // keep trying to send the packet to the proxy until it works, since distributed systems are eventually consistent.
        let mut response: String = "not-found".into();
        for i in 0..30 {
            println!("Connection Attempt: {i}");

            // returns the nae of the GameServer. This proves we are routing the the allocated
            // GameServer with the correct token attached.
            socket
                .send_to(format!("GAMESERVER{token}").as_bytes(), proxy_address)
                .await
                .unwrap();

            let result = timeout(Duration::from_secs(1), rx.recv()).await;
            if let Ok(Some(value)) = result {
                response = value;
                break;
            }
        }
        assert_eq!(format!("NAME: {}\n", gs.name_unchecked()), response);

        // let's remove the token from the gameserver, which should remove access.
        let mut gs = gameservers.get(gs.name_unchecked().as_str()).await.unwrap();
        let name = gs.name_unchecked();
        gs.metadata
            .annotations
            .as_mut()
            .map(|annotations| annotations.remove(token_key).unwrap());
        gameservers.replace(name.as_str(), &pp, &gs).await.unwrap();

        // now we should send a packet, and not get a response.
        let mut failed = false;
        for i in 0..30 {
            println!("Disconnection Attempt: {i}");
            socket
                .send_to(format!("GAMESERVER{token}").as_bytes(), proxy_address)
                .await
                .unwrap();

            let result = timeout(Duration::from_secs(1), rx.recv()).await;
            if result.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed, "Packet should have failed");
    }

    /// Creates Quilkin xDS management instance that is in the mode to watch Agones GameServers
    /// in this test namespace
    async fn agones_control_plane(client: &Client, deployments: Api<Deployment>) {
        let services: Api<Service> = client.namespaced_api();
        let service_accounts: Api<ServiceAccount> = client.namespaced_api();
        let cluster_roles: Api<ClusterRole> = Api::all(client.kubernetes.clone());
        let role_bindings: Api<RoleBinding> = client.namespaced_api();
        let pp = PostParams::default();

        // create all the rbac rules
        let rbac_name = "quilkin-agones";
        let rbac_meta = ObjectMeta {
            name: Some(rbac_name.into()),
            ..Default::default()
        };
        let service_account = ServiceAccount {
            metadata: rbac_meta.clone(),
            ..Default::default()
        };
        service_accounts
            .create(&pp, &service_account)
            .await
            .unwrap();

        // Delete the cluster role if it already exists, since it's cluster wide.
        match cluster_roles
            .delete(rbac_name, &DeleteParams::default())
            .await
        {
            Ok(_) => {}
            Err(err) => println!("Cluster role not found: {err}"),
        };
        let cluster_role = ClusterRole {
            metadata: rbac_meta.clone(),
            rules: Some(vec![
                PolicyRule {
                    api_groups: Some(vec!["agones.dev".into()]),
                    resources: Some(vec!["gameservers".into()]),
                    verbs: ["get", "list", "watch"].map(String::from).to_vec(),
                    ..Default::default()
                },
                PolicyRule {
                    api_groups: Some(vec!["".into()]),
                    resources: Some(vec!["configmaps".into()]),
                    verbs: ["get", "list", "watch"].map(String::from).to_vec(),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        cluster_roles.create(&pp, &cluster_role).await.unwrap();

        let binding = RoleBinding {
            metadata: rbac_meta,
            subjects: Some(vec![Subject {
                kind: "User".into(),
                name: format!("system:serviceaccount:{}:{rbac_name}", client.namespace),
                api_group: Some("rbac.authorization.k8s.io".into()),
                ..Default::default()
            }]),
            role_ref: RoleRef {
                api_group: "rbac.authorization.k8s.io".into(),
                kind: "ClusterRole".into(),
                name: rbac_name.into(),
            },
        };
        role_bindings.create(&pp, &binding).await.unwrap();

        // Setup the xDS Agones provider server
        let args = [
            "manage",
            "agones",
            "--config-namespace",
            client.namespace.as_str(),
            "--gameservers-namespace",
            client.namespace.as_str(),
        ]
        .map(String::from)
        .to_vec();
        let mut container = quilkin_container(client, Some(args), None);
        container.ports = Some(vec![ContainerPort {
            container_port: 7000,
            ..Default::default()
        }]);
        let labels = BTreeMap::from([("role".to_string(), "xds".to_string())]);
        let deployment = Deployment {
            metadata: ObjectMeta {
                name: Some("quilkin-manage-agones".into()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(1),
                selector: LabelSelector {
                    match_expressions: None,
                    match_labels: Some(labels.clone()),
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels.clone()),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![container],
                        service_account_name: Some(rbac_name.into()),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        let deployment = deployments.create(&pp, &deployment).await.unwrap();

        let service = Service {
            metadata: ObjectMeta {
                name: Some("quilkin-manage-agones".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                selector: Some(labels),
                ports: Some(vec![ServicePort {
                    protocol: Some("TCP".into()),
                    port: 80,
                    target_port: Some(IntOrString::Int(7000)),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };
        services.create(&pp, &service).await.unwrap();

        // make sure the deployment and service are ready
        let name = deployment.name_unchecked();
        timeout(
            Duration::from_secs(30),
            await_condition(deployments.clone(), name.as_str(), is_deployment_ready()),
        )
        .await
        .expect("xDS provider deployment should be ready")
        .unwrap();
    }

    /// create a Deployment with a singular Quilkin proxy, that is configured
    /// to be attached to the Quilkin Agones xDS server in `agones_control_plane()`.
    async fn quilkin_proxy_deployment(
        client: &Client,
        config_maps: Api<ConfigMap>,
        deployments: Api<Deployment>,
    ) -> SocketAddr {
        let pp = PostParams::default();
        let config = r#"
version: v1alpha1
management_servers:
  - address: http://quilkin-manage-agones:80
"#;

        let config_map = config_maps
            .create(&pp, &quilkin_config_map(config))
            .await
            .unwrap();
        let mount_name = "config";
        let mut container =
            quilkin_container(client, Some(vec!["proxy".into()]), Some(mount_name.into()));

        // we'll use a host port, since spinning up a load balancer takes a long time.
        // we know that port 7000 is open because this is an Agones cluster and it has associated
        // firewall rules , and even if we conflict with a GameServer
        // the k8s scheduler will move us to another node.
        let host_port: u16 = 7005;
        container.ports = Some(vec![ContainerPort {
            container_port: 7000,
            host_port: Some(host_port as i32),
            protocol: Some("UDP".into()),
            ..Default::default()
        }]);

        let labels = BTreeMap::from([("role".to_string(), "proxy".to_string())]);
        let deployment = Deployment {
            metadata: ObjectMeta {
                name: Some(PROXY_DEPLOYMENT.into()),
                labels: Some(labels.clone()),
                ..Default::default()
            },
            spec: Some(DeploymentSpec {
                replicas: Some(1),
                selector: LabelSelector {
                    match_expressions: None,
                    match_labels: Some(labels.clone()),
                },
                template: PodTemplateSpec {
                    metadata: Some(ObjectMeta {
                        labels: Some(labels.clone()),
                        ..Default::default()
                    }),
                    spec: Some(PodSpec {
                        containers: vec![container],
                        volumes: Some(vec![Volume {
                            name: mount_name.into(),
                            config_map: Some(ConfigMapVolumeSource {
                                name: Some(config_map.name_unchecked()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };

        let deployment = deployments.create(&pp, &deployment).await.unwrap();
        let name = deployment.name_unchecked();
        // should not be ready, since there are no endpoints, but let's wait 3 seconds, make sure it doesn't do something we don't expect
        let result = timeout(
            Duration::from_secs(3),
            await_condition(deployments.clone(), name.as_str(), is_deployment_ready()),
        )
        .await;
        assert!(result.is_err());

        // get the address to send data to
        let pods = client.namespaced_api::<Pod>();
        let list = pods
            .list(&ListParams {
                label_selector: Some("role=proxy".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(1, list.items.len());

        let nodes: Api<Node> = Api::all(client.kubernetes.clone());
        let name = list.items[0]
            .spec
            .as_ref()
            .unwrap()
            .node_name
            .as_ref()
            .unwrap();
        let node = nodes.get(name.as_str()).await.unwrap();
        let external_ip = node
            .status
            .unwrap()
            .addresses
            .unwrap()
            .iter()
            .find(|addr| addr.type_ == "ExternalIP")
            .unwrap()
            .address
            .clone();

        SocketAddr::new(external_ip.parse().unwrap(), host_port)
    }
}
