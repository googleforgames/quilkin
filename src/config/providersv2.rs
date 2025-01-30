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

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use futures::TryStreamExt;
use tokio::task::JoinHandle;

const RETRIES: u32 = 25;
const BACKOFF_STEP: std::time::Duration = std::time::Duration::from_millis(250);
const MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// The available xDS source provider.
#[derive(Clone, Debug, Default, clap::Args)]
pub struct Providers {
    /// Watches Agones' game server CRDs for `Allocated` game server endpoints,
    /// and for a `ConfigMap` that specifies the filter configuration.
    #[arg(
        long = "provider.k8s",
        env = "QUILKIN_PROVIDERS_K8S",
        default_value_t = false
    )]
    k8s_enabled: bool,

    #[arg(
        long = "provider.k8s.namespace",
        env = "QUILKIN_PROVIDERS_K8S_NAMESPACE",
        default_value_t = From::from("default"),
        requires("k8s_enabled"),
    )]
    k8s_namespace: String,

    #[arg(
        long = "provider.k8s.agones",
        env = "QUILKIN_PROVIDERS_K8S_AGONES",
        default_value_t = false
    )]
    agones_enabled: bool,

    #[arg(
        long = "provider.k8s.agones.namespace",
        env = "QUILKIN_PROVIDERS_K8S_AGONES_NAMESPACE",
        default_value_t = From::from("default"),
        requires("agones_enabled"),
    )]
    agones_namespace: String,

    /// If specified, filters the available gameserver addresses to the one that
    /// matches the specified type
    #[arg(
        long = "provider.k8s.agones.address_type",
        env = "QUILKIN_PROVIDERS_K8S_AGONES_ADDRESS_TYPE",
        requires("agones_enabled")
    )]
    pub address_type: Option<String>,
    /// If specified, additionally filters the gameserver address by its ip kind
    #[arg(
        long = "provider.k8s.agones.ip_kind",
        env = "QUILKIN_PROVIDERS_K8S_AGONES_IP_KIND",
        requires("address_type"),
        value_enum
    )]
    pub ip_kind: Option<crate::config::AddrKind>,

    #[arg(
        long = "provider.fs",
        env = "QUILKIN_PROVIDERS_FS",
        conflicts_with("k8s_enabled"),
        default_value_t = false
    )]
    fs_enabled: bool,

    #[arg(
        long = "provider.fs.path",
        env = "QUILKIN_PROVIDERS_FS_PATH",
        requires("fs_enabled"),
        default_value = "/etc/quilkin/config.yaml"
    )]
    fs_path: std::path::PathBuf,
    /// One or more `quilkin relay` endpoints to push configuration changes to.
    #[clap(
        long = "provider.mds.endpoints",
        env = "QUILKIN_PROVIDERS_MDS_ENDPOINTS"
    )]
    pub relay: Vec<tonic::transport::Endpoint>,
    /// The remote URL or local file path to retrieve the Maxmind database.
    #[clap(
        long = "provider.mmdb.endpoints",
        env = "QUILKIN_PROVIDERS_MMDB_ENDPOINTS"
    )]
    pub mmdb: Option<crate::net::maxmind_db::Source>,
    /// One or more socket addresses to forward packets to.
    #[clap(
        long = "provider.static.endpoints",
        env = "QUILKIN_PROVIDERS_STATIC_ENDPOINTS"
    )]
    pub endpoints: Vec<SocketAddr>,
    /// Assigns dynamic tokens to each address in the `--to` argument
    ///
    /// Format is `<number of unique tokens>:<length of token suffix for each packet>`
    #[clap(
        long = "provider.static.endpoint_tokens",
        env = "QUILKIN_PROVIDERS_STATIC_ENDPOINT_TOKENS",
        requires("endpoints")
    )]
    pub endpoint_tokens: Option<String>,
}

impl Providers {
    pub fn agones(mut self) -> Self {
        self.agones_enabled = true;
        self
    }

    pub fn agones_namespace(mut self, ns: impl Into<String>) -> Self {
        self.agones_namespace = ns.into();
        self
    }

    pub fn fs(mut self) -> Self {
        self.fs_enabled = true;
        self
    }

    pub fn fs_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.fs_path = path.into();
        self
    }

    pub fn k8s(mut self) -> Self {
        self.k8s_enabled = true;
        self
    }

    pub fn k8s_namespace(mut self, ns: impl Into<String>) -> Self {
        self.k8s_namespace = ns.into();
        self
    }

    fn static_enabled(&self) -> bool {
        !self.endpoints.is_empty()
    }

    pub fn spawn_static_provider(
        &self,
        config: Arc<crate::config::Config>,
    ) -> crate::Result<JoinHandle<crate::Result<()>>> {
        let endpoint_tokens = self
            .endpoint_tokens
            .as_ref()
            .map(|tt| {
                let Some((count, length)) = tt.split_once(':') else {
                    eyre::bail!("--to-tokens `{tt}` is invalid, it must have a `:` separator")
                };

                let count = count.parse()?;
                let length = length.parse()?;

                Ok(crate::components::proxy::ToTokens { count, length })
            })
            .transpose()?;

        let endpoints = if let Some(tt) = endpoint_tokens {
            let (unique, overflow) = 256u64.overflowing_pow(tt.length as _);
            if overflow {
                panic!(
                    "can't generate {} tokens of length {} maximum is {}",
                    self.endpoints.len() * tt.count,
                    tt.length,
                    u64::MAX,
                );
            }

            if unique < (self.endpoints.len() * tt.count) as u64 {
                panic!(
                    "we require {} unique tokens but only {unique} can be generated",
                    self.endpoints.len() * tt.count,
                );
            }

            {
                use crate::filters::StaticFilter as _;
                config.filters.store(Arc::new(
                    crate::filters::FilterChain::try_create([
                        crate::filters::Capture::as_filter_config(
                            crate::filters::capture::Config {
                                metadata_key: crate::filters::capture::CAPTURED_BYTES.into(),
                                strategy: crate::filters::capture::Strategy::Suffix(
                                    crate::filters::capture::Suffix {
                                        size: tt.length as _,
                                        remove: true,
                                    },
                                ),
                            },
                        )
                        .unwrap(),
                        crate::filters::TokenRouter::as_filter_config(None).unwrap(),
                    ])
                    .unwrap(),
                ));
            }

            let count = tt.count as u64;

            self.endpoints
                .iter()
                .enumerate()
                .map(|(ind, sa)| {
                    let mut tokens = std::collections::BTreeSet::new();
                    let start = ind as u64 * count;
                    for i in start..(start + count) {
                        tokens.insert(i.to_le_bytes()[..tt.length].to_vec());
                    }

                    crate::net::endpoint::Endpoint::with_metadata(
                        (*sa).into(),
                        crate::net::endpoint::Metadata { tokens },
                    )
                })
                .collect()
        } else {
            self.endpoints
                .iter()
                .cloned()
                .map(crate::net::endpoint::Endpoint::from)
                .collect()
        };

        tracing::info!(
            provider = "static",
            endpoints = serde_json::to_string(&endpoints).unwrap(),
            "setting endpoints"
        );
        config.clusters.modify(|clusters| {
            clusters.insert(None, endpoints);
        });

        Ok(tokio::spawn(std::future::pending()))
    }

    pub fn spawn_k8s_provider(
        &self,
        health_check: Arc<AtomicBool>,
        locality: Option<crate::net::endpoint::Locality>,
        config: Arc<crate::config::Config>,
    ) -> JoinHandle<crate::Result<()>> {
        let agones_namespace = self.agones_namespace.clone();
        let agones_enabled = self.agones_enabled;
        let k8s_enabled = self.k8s_enabled;
        let k8s_namespace = self.k8s_namespace.clone();
        let selector = self
            .address_type
            .as_ref()
            .map(|at| crate::config::AddressSelector {
                name: at.clone(),
                kind: self.ip_kind.unwrap_or(crate::config::AddrKind::Any),
            });

        let task = {
            let config = config.clone();
            let health_check = health_check.clone();
            let agones_namespace: String = agones_namespace.clone();
            let selector = selector.clone();
            let locality = locality.clone();
            let health_check = health_check.clone();

            move || {
                let config = config.clone();
                let health_check = health_check.clone();
                let agones_namespace: String = agones_namespace.clone();
                let k8s_namespace: String = k8s_namespace.clone();
                let selector = selector.clone();
                let locality = locality.clone();
                let health_check = health_check.clone();

                async move {
                    let client = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        kube::Client::try_default(),
                    )
                    .await??;

                    let k8s_stream = if k8s_enabled {
                        either::Left(Self::result_stream(
                            health_check.clone(),
                            crate::config::providers::k8s::update_filters_from_configmap(
                                client.clone(),
                                k8s_namespace.clone(),
                                config.clone(),
                            ),
                        ))
                    } else {
                        either::Right(std::future::pending())
                    };

                    let gs_stream = if agones_enabled {
                        either::Left(Self::result_stream(
                            health_check.clone(),
                            crate::config::watch::agones::watch_gameservers(
                                client,
                                agones_namespace.clone(),
                                config.clone(),
                                locality.clone(),
                                selector.clone(),
                            ),
                        ))
                    } else {
                        either::Right(std::future::pending())
                    };

                    tokio::select! {
                        result = gs_stream => result,
                        result = k8s_stream => result,
                    }
                }
            }
        };

        tokio::spawn(Self::task(health_check.clone(), task))
    }

    async fn result_stream<T>(
        health_check: Arc<AtomicBool>,
        stream: impl futures::Stream<Item = crate::Result<T>>,
    ) -> crate::Result<()> {
        tokio::pin!(stream);
        loop {
            match stream.try_next().await {
                Ok(Some(_)) => health_check.store(true, Ordering::SeqCst),
                Ok(None) => break Err(eyre::eyre!("kubernetes watch stream terminated")),
                Err(error) => break Err(error),
            }
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub fn spawn_providers(
        self,
        config: &std::sync::Arc<crate::Config>,
        health_check: Arc<AtomicBool>,
        locality: Option<crate::net::endpoint::Locality>,
    ) -> tokio::task::JoinHandle<crate::Result<()>> {
        if self.k8s_enabled || self.agones_enabled {
            self.spawn_k8s_provider(health_check, locality, config.clone())
        } else if self.fs_enabled {
            let config = config.clone();
            tokio::spawn(Self::task(health_check.clone(), {
                let path = self.fs_path.clone();
                let health_check = health_check.clone();
                move || {
                    crate::config::watch::fs(
                        config.clone(),
                        health_check.clone(),
                        path.clone(),
                        locality.clone(),
                    )
                }
            }))
        } else if self.static_enabled() {
            self.spawn_static_provider(config.clone()).unwrap()
        } else {
            tokio::spawn(async move { Ok(()) })
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
