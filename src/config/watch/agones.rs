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

pub mod crd;

use futures::TryStreamExt;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::runtime::watcher::Event;
use std::sync::Arc;

use crate::{
    cluster::ClusterMap,
    endpoint::{Endpoint, LocalityEndpoints},
    Config,
};
use crd::GameServer;

pub async fn watch(
    gameservers_namespace: impl AsRef<str>,
    config_namespace: impl AsRef<str>,
    config: Arc<Config>,
) -> crate::Result<()> {
    let client = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        kube::Client::try_default(),
    )
    .await??;
    let config_namespace = config_namespace.as_ref();
    let gameservers_namespace = gameservers_namespace.as_ref();
    let configmap: kube::Api<ConfigMap> = kube::Api::namespaced(client.clone(), config_namespace);
    let gameservers: kube::Api<GameServer> = kube::Api::namespaced(client, gameservers_namespace);

    let gs_writer = kube::runtime::reflector::store::Writer::<GameServer>::default();
    let config_writer = kube::runtime::reflector::store::Writer::<ConfigMap>::default();
    let configmap_stream = kube::runtime::watcher(
        configmap,
        kube::api::ListParams::default().labels("quilkin.dev/configmap=true"),
    );
    let gameserver_stream = kube::runtime::watcher(gameservers, kube::api::ListParams::default());
    let configmap_reflector = kube::runtime::reflector(config_writer, configmap_stream);
    let gameserver_reflector = kube::runtime::reflector(gs_writer, gameserver_stream);
    let this = Watcher { config };

    let this = this.clone();
    tokio::pin!(configmap_reflector);
    tokio::pin!(gameserver_reflector);

    loop {
        let new_event: Option<either::Either<Event<ConfigMap>, Event<GameServer>>> = tokio::select! {
            event = configmap_reflector.try_next() => event?.map(either::Left),
            event = gameserver_reflector.try_next() => event?.map(either::Right),
        };

        match new_event {
            Some(either::Left(configmap)) => {
                this.handle_configmap_event(configmap).await?;
            }
            Some(either::Right(gameserver)) => {
                this.handle_gameserver_event(gameserver).await?;
            }
            None => break Err(eyre::eyre!("Kubernetes stream unexpectedly ended")),
        }
    }
}

#[derive(Clone)]
pub struct Watcher {
    config: Arc<Config>,
}

impl Watcher {
    async fn handle_configmap_event(&self, event: Event<ConfigMap>) -> Result<(), tonic::Status> {
        tracing::trace!("new configmap event");

        let configmap = match event {
            Event::Applied(configmap) => configmap,
            Event::Restarted(configmaps) => match configmaps.get(0) {
                Some(configmap) => configmap.clone(),
                None => return Ok(()),
            },
            Event::Deleted(_) => {
                self.config.filters.remove();
                return Ok(());
            }
        };

        self.update_configmap(configmap)
    }

    fn update_configmap(&self, configmap: ConfigMap) -> Result<(), tonic::Status> {
        let config = configmap
            .data
            .ok_or_else(|| tonic::Status::internal("No configmap data present"))?;
        let config = config
            .get("quilkin.yaml")
            .ok_or_else(|| tonic::Status::internal("No quilkin.yaml present in configmap."))?;

        let data: serde_json::Map<String, serde_json::Value> =
            serde_yaml::from_str(config).map_err(|err| tonic::Status::internal(err.to_string()))?;

        if let Some(filters) = data
            .get("filters")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| tonic::Status::internal(error.to_string()))?
        {
            self.config.filters.store(Arc::new(filters));
        }

        Ok(())
    }

    async fn handle_gameserver_event(&self, event: Event<GameServer>) -> Result<(), tonic::Status> {
        match event {
            Event::Applied(server) => {
                if !server.is_allocated() {
                    return Ok(());
                }

                let endpoint = Endpoint::try_from(server)?;
                tracing::trace!(endpoint=%serde_json::to_value(&endpoint).unwrap(), "Adding endpoint");
                self.config.clusters.modify(|clusters| {
                    clusters.default_cluster_mut().insert(endpoint.clone());
                });
                tracing::trace!(clusters=%serde_json::to_value(&self.config.clusters.load()).unwrap(), "current clusters");
            }

            Event::Restarted(servers) => {
                let servers: Vec<_> = servers
                    .into_iter()
                    .filter(GameServer::is_allocated)
                    .collect();
                let endpoints = LocalityEndpoints::try_from(servers)?;
                tracing::trace!(?endpoints, "Restarting with endpoints");
                self.config
                    .clusters
                    .store(Arc::new(ClusterMap::new_with_default_cluster(endpoints)));
            }

            Event::Deleted(server) => {
                let endpoint = Endpoint::try_from(server)?;
                tracing::trace!(?endpoint, "Deleting endpoint");
                self.config.clusters.modify(|clusters| {
                    for locality in clusters.default_cluster_mut().localities.iter_mut() {
                        locality.remove(&endpoint);
                    }
                });
            }
        };

        self.config.apply_metrics();
        Ok(())
    }
}
