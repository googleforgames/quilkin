/*
 * Copyright 2023 Google LLC All Rights Reserved.
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, time::Duration};

    use k8s_openapi::{
        api::{
            apps::v1::{Deployment, DeploymentSpec},
            core::v1::{
                ConfigMap, PodSpec, PodTemplateSpec, Service, ServiceAccount, ServicePort,
                ServiceSpec,
            },
            rbac::v1::{ClusterRole, RoleBinding},
        },
        apimachinery::pkg::{
            apis::meta::v1::{LabelSelector, ObjectMeta},
            util::intstr::IntOrString,
        },
    };
    use kube::{
        api::{DeleteParams, PostParams},
        runtime::wait::await_condition,
        Api, ResourceExt,
    };
    use serial_test::serial;
    use tokio::time::timeout;

    use quilkin::{
        config::providers::k8s::agones::{Fleet, GameServer},
        test::TestHelper,
    };

    use crate::{
        create_agones_rbac_read_account, create_token_router_config, create_tokenised_gameserver,
        debug_pods, is_deployment_ready, quilkin_container, quilkin_proxy_deployment, Client,
        TOKEN_KEY,
    };

    #[tokio::test]
    #[serial]
    /// Test for Agones Provider integration. Since this will look at all GameServers in the namespace
    /// for this test, we should only run Agones integration test in a serial manner, since they
    /// could easily collide with each other.
    async fn agones_token_router() {
        run_test(true, true, false).await;
        run_test(true, false, true).await;
        run_test(false, true, true).await;
    }

    async fn run_test(proxy: bool, relay: bool, agent: bool) {
        let client = Client::new().await;
        let config_maps: Api<ConfigMap> = client.namespaced_api();
        let deployments: Api<Deployment> = client.namespaced_api();
        let fleets: Api<Fleet> = client.namespaced_api();
        let gameservers: Api<GameServer> = client.namespaced_api();

        let pp = PostParams::default();
        let dp = DeleteParams::default();

        let config_map = create_token_router_config(&config_maps).await;
        agones_agent_deployment(&client, deployments.clone(), relay, agent).await;

        let relay_proxy_name = "quilkin-relay-proxy";
        let proxy_address = quilkin_proxy_deployment(
            &client,
            deployments.clone(),
            relay_proxy_name.into(),
            7005,
            "http://quilkin-relay-agones:7800".into(),
            proxy,
        )
        .await;

        let token = "789";
        let gs = create_tokenised_gameserver(fleets, gameservers.clone(), token).await;
        let gs_address = crate::gameserver_address(&gs);

        let mut t = TestHelper::default();
        let (mut rx, socket) = t.open_socket_and_recv_multiple_packets().await;
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
        if timeout(
            Duration::from_secs(30),
            await_condition(deployments.clone(), relay_proxy_name, is_deployment_ready()),
        )
        .await
        .is_err()
        {
            debug_pods(&client, format!("role={relay_proxy_name}")).await;
            panic!("Quilkin proxy deployment should be ready");
        }

        // keep trying to send the packet to the proxy until it works, since distributed systems are eventually consistent.
        let mut response: String = "not-found".into();
        for i in 0..30 {
            println!("Connection Attempt: {i}");

            // returns the name of the GameServer. This proves we are routing the allocated
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
            .map(|annotations| annotations.remove(TOKEN_KEY).unwrap());
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
        if !failed {
            debug_pods(&client, format!("role={relay_proxy_name}")).await;
            debug_pods(&client, "role=xds".into()).await;
        }
        assert!(failed, "Packet should have failed");

        // cleanup
        config_maps
            .delete(&config_map.name_unchecked(), &dp)
            .await
            .unwrap();
        deployments
            .delete_collection(&dp, &kube::api::ListParams::default())
            .await
            .unwrap();
    }

    /// Deploys the Agent and Relay Server Deployments and Services
    async fn agones_agent_deployment(
        client: &Client,
        deployments: Api<Deployment>,
        relay: bool,
        agent: bool,
    ) {
        let service_accounts: Api<ServiceAccount> = client.namespaced_api();
        let cluster_roles: Api<ClusterRole> = Api::all(client.kubernetes.clone());
        let role_bindings: Api<RoleBinding> = client.namespaced_api();
        let services: Api<Service> = client.namespaced_api();

        let pp = PostParams::default();

        let rbac_name =
            create_agones_rbac_read_account(client, service_accounts, cluster_roles, role_bindings)
                .await;

        // Setup the relay
        let args = [
            "relay",
            "agones",
            "--config-namespace",
            client.namespace.as_str(),
        ]
        .map(String::from)
        .to_vec();
        let labels = BTreeMap::from([("role".to_string(), "relay".to_string())]);
        let deployment = Deployment {
            metadata: ObjectMeta {
                name: Some("quilkin-relay-agones".into()),
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
                        containers: vec![quilkin_container(client, Some(args), None, relay)],
                        service_account_name: Some(rbac_name.clone()),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let relay_deployment = deployments.create(&pp, &deployment).await.unwrap();

        // relay service
        let service = Service {
            metadata: ObjectMeta {
                name: Some("quilkin-relay-agones".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                selector: Some(labels),
                ports: Some(vec![
                    ServicePort {
                        name: Some("ads".into()),
                        protocol: Some("TCP".into()),
                        port: 7800,
                        target_port: Some(IntOrString::Int(7800)),
                        ..Default::default()
                    },
                    ServicePort {
                        name: Some("cpds".into()),
                        protocol: Some("TCP".into()),
                        port: 7900,
                        target_port: Some(IntOrString::Int(7900)),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        services.create(&pp, &service).await.unwrap();

        let name = relay_deployment.name_unchecked();
        let result = timeout(
            Duration::from_secs(30),
            await_condition(deployments.clone(), name.as_str(), is_deployment_ready()),
        )
        .await;
        if result.is_err() {
            debug_pods(client, "role=relay".into()).await;

            panic!("Relay Deployment should be ready");
        }
        result.unwrap().expect("Should have a relay deployment");

        // agent deployment
        let args = [
            "agent",
            "--relay",
            "http://quilkin-relay-agones:7900",
            "agones",
            "--config-namespace",
            client.namespace.as_str(),
            "--gameservers-namespace",
            client.namespace.as_str(),
        ]
        .map(String::from)
        .to_vec();
        let labels = BTreeMap::from([("role".to_string(), "agent".to_string())]);
        let deployment = Deployment {
            metadata: ObjectMeta {
                name: Some("quilkin-agones-agent".into()),
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
                        containers: vec![quilkin_container(client, Some(args), None, agent)],
                        service_account_name: Some(rbac_name),
                        ..Default::default()
                    }),
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        let agent_deployment = deployments.create(&pp, &deployment).await.unwrap();
        let name = agent_deployment.name_unchecked();
        let result = timeout(
            Duration::from_secs(30),
            await_condition(deployments.clone(), name.as_str(), is_deployment_ready()),
        )
        .await;
        if result.is_err() {
            debug_pods(client, "role=agent".into()).await;
            panic!("Agent Deployment should be ready");
        }
        result.unwrap().expect("Should have an agent deployment");
    }
}
