/*
 * Copyright 2024 Google LLC All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
pub mod k8s;

const RETRIES: u32 = 25;
const BACKOFF_STEP: std::time::Duration = std::time::Duration::from_millis(250);
const MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// The available xDS source providers.
#[derive(Clone, Debug, clap::Subcommand)]
pub enum Providers {
    /// Watches Agones' game server CRDs for `Allocated` game server endpoints,
    /// and for a `ConfigMap` that specifies the filter configuration.
    Agones {
        /// The namespace under which the configmap is stored.
        #[clap(short, long, env = "QUILKIN_AGONES_CONFIG_NAMESPACE")]
        config_namespace: Option<String>,
        /// The namespace under which the game servers run.
        #[clap(
            short,
            long,
            env = "QUILKIN_AGONES_GAMESERVERS_NAMESPACE",
            default_value = "default"
        )]
        gameservers_namespace: String,
    },

    /// Watches for changes to the file located at `path`.
    File {
        /// The path to the source config.
        #[clap(env = "QUILKIN_FS_PATH")]
        path: std::path::PathBuf,
    },
}

impl Providers {
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn spawn(
        self,
        config: std::sync::Arc<crate::Config>,
        health_check: Arc<AtomicBool>,
        locality: Option<crate::net::endpoint::Locality>,
        address_selector: Option<crate::config::AddressSelector>,
        is_agent: bool,
    ) -> tokio::task::JoinHandle<crate::Result<()>> {
        match self {
            Self::Agones {
                gameservers_namespace,
                config_namespace,
            } => tokio::spawn(async move {
                let config_namespace = match (config_namespace, is_agent) {
                    (Some(cns), false) => Some(cns),
                    (None, true) => None,
                    (None, false) => Some("default".into()),
                    (Some(cns), true) => {
                        tracing::warn!("'{cns}' via --config-namespace, -c, or QUILKIN_AGONES_CONFIG_NAMESPACE is ignored for agents and should not be set");
                        None
                    }
                };

                Self::task(health_check.clone(), {
                    let health_check = health_check.clone();
                    move || {
                        crate::config::watch::agones(
                            gameservers_namespace.clone(),
                            config_namespace.clone(),
                            health_check.clone(),
                            locality.clone(),
                            config.clone(),
                            address_selector.clone(),
                        )
                    }
                })
                .await
            }),
            Self::File { path } => tokio::spawn(Self::task(health_check.clone(), {
                let path = path.clone();
                let health_check = health_check.clone();
                move || {
                    crate::config::watch::fs(
                        config.clone(),
                        health_check.clone(),
                        path.clone(),
                        locality.clone(),
                    )
                }
            })),
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn task<F>(
        health_check: Arc<AtomicBool>,
        task: impl FnMut() -> F,
    ) -> crate::Result<()>
    where
        F: std::future::Future<Output = crate::Result<()>>,
    {
        tryhard::retry_fn(task)
            .retries(RETRIES)
            .exponential_backoff(BACKOFF_STEP)
            .max_delay(MAX_DELAY)
            .on_retry(|attempt, _, error: &eyre::Error| {
                health_check.store(false, Ordering::SeqCst);
                let error = error.to_string();
                async move {
                    tracing::warn!(%attempt, %error, "provider task error, retrying");
                }
            })
            .await
    }
}
