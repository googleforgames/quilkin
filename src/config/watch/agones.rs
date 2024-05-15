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

use futures::TryStreamExt;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::{net::endpoint::Locality, Config};

pub async fn watch(
    gameservers_namespace: impl AsRef<str>,
    config_namespace: impl AsRef<str>,
    health_check: Arc<AtomicBool>,
    locality: Option<Locality>,
    config: Arc<Config>,
) -> crate::Result<()> {
    let client = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        kube::Client::try_default(),
    )
    .await??;
    let configmap_reflector = crate::config::providers::k8s::update_filters_from_configmap(
        client.clone(),
        config_namespace,
        config.clone(),
    );
    let gameserver_reflector = crate::config::providers::k8s::update_endpoints_from_gameservers(
        client,
        gameservers_namespace,
        config.clone(),
        locality,
    );
    tokio::pin!(configmap_reflector);
    tokio::pin!(gameserver_reflector);

    loop {
        let result = tokio::select! {
            result = configmap_reflector.try_next() => result,
            result = gameserver_reflector.try_next() => result,
        };

        match result {
            Ok(Some(_)) => health_check.store(true, Ordering::SeqCst),
            Ok(None) => break Err(eyre::eyre!("kubernetes watch stream terminated")),
            Err(error) => break Err(error),
        }
    }
}
