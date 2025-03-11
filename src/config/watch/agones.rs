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
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::net::endpoint::Locality;

pub use crate::config::providers::k8s::update_endpoints_from_gameservers as watch_gameservers;

pub async fn watch(
    gameservers_namespace: String,
    config_namespace: Option<String>,
    health_check: Arc<AtomicBool>,
    locality: Option<Locality>,
    filters: crate::config::Slot<crate::filters::FilterChain>,
    clusters: crate::config::Watch<crate::net::ClusterMap>,
    address_selector: Option<crate::config::AddressSelector>,
) -> crate::Result<()> {
    let client = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        kube::Client::try_default(),
    )
    .await??;

    let mut configmap_reflector: std::pin::Pin<Box<dyn futures::Stream<Item = _> + Send>> =
        if let Some(cns) = config_namespace {
            Box::pin(
                crate::config::providers::k8s::update_filters_from_configmap(
                    client.clone(),
                    cns,
                    filters,
                ),
            )
        } else {
            Box::pin(futures::stream::pending())
        };

    let gameserver_reflector = crate::config::providers::k8s::update_endpoints_from_gameservers(
        client,
        gameservers_namespace,
        clusters,
        locality,
        address_selector,
    );

    tokio::pin!(gameserver_reflector);

    loop {
        let result = tokio::select! {
            result = configmap_reflector.try_next() => result,
            result = gameserver_reflector.try_next() => result,
        };

        match result
            .and_then(|opt| opt.ok_or_else(|| eyre::eyre!("kubernetes watch stream terminated")))
        {
            Ok(_) => {
                crate::metrics::k8s::active(true);
                health_check.store(true, Ordering::SeqCst);
            }
            Err(error) => break Err(error),
        }
    }
}
