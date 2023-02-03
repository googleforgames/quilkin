/*
 * Copyright 2022 Google LLC
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

pub const PORT: u16 = 7800;

/// Runs Quilkin as a xDS management server, using `provider` as
/// a configuration source.
#[derive(clap::Args, Clone)]
pub struct Manage {
    /// The TCP port to listen to, to serve discovery responses.
    #[clap(short, long, env = super::PORT_ENV_VAR, default_value_t = PORT)]
    port: u16,
    /// The `region` to set in the cluster map for any provider
    /// endpoints discovered.
    #[clap(long, env = "QUILKIN_REGION")]
    region: Option<String>,
    /// The `zone` in the `region` to set in the cluster map for any provider
    /// endpoints discovered.
    #[clap(long, env = "QUILKIN_ZONE")]
    zone: Option<String>,
    /// The `sub_zone` in the `zone` in the `region` to set in the cluster map
    /// for any provider endpoints discovered.
    #[clap(long, env = "QUILKIN_SUB_ZONE")]
    sub_zone: Option<String>,
    /// The configuration source for a management server.
    #[clap(subcommand)]
    pub provider: Providers,
}

/// The available xDS source providers.
#[derive(Clone, clap::Subcommand)]
pub enum Providers {
    /// Watches Agones' game server CRDs for `Allocated` game server endpoints,
    /// and for a `ConfigMap` that specifies the filter configuration.
    Agones {
        /// The namespace under which the configmap is stored.
        #[clap(short, long, default_value = "default")]
        config_namespace: String,
        /// The namespace under which the game servers run.
        #[clap(short, long, default_value = "default")]
        gameservers_namespace: String,
    },

    /// Watches for changes to the file located at `path`.
    File {
        /// The path to the source config.
        path: std::path::PathBuf,
    },
}

impl Manage {
    pub async fn manage(&self, config: std::sync::Arc<crate::Config>) -> crate::Result<()> {
        let locality = (self.region.is_some() || self.zone.is_some() || self.sub_zone.is_some())
            .then(|| crate::endpoint::Locality {
                region: self.region.clone().unwrap_or_default(),
                zone: self.zone.clone().unwrap_or_default(),
                sub_zone: self.sub_zone.clone().unwrap_or_default(),
            });

        if let Some(locality) = &locality {
            config
                .clusters
                .modify(|map| map.update_unlocated_endpoints(locality));
        }

        let provider_task = {
            const PROVIDER_RETRIES: u32 = 25;
            const PROVIDER_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);
            let config = config.clone();

            tryhard::retry_fn(move || match &self.provider {
                Providers::Agones {
                    gameservers_namespace,
                    config_namespace,
                } => tokio::spawn(crate::config::watch::agones(
                    gameservers_namespace.clone(),
                    config_namespace.clone(),
                    locality.clone(),
                    config.clone(),
                )),
                Providers::File { path } => tokio::spawn(crate::config::watch::fs(
                    config.clone(),
                    path.clone(),
                    locality.clone(),
                )),
            })
            .retries(PROVIDER_RETRIES)
            .exponential_backoff(PROVIDER_BACKOFF)
            .on_retry(|_, _, error| {
                let error = error.to_string();
                async move {
                    tracing::warn!(%error, "provider task error, retrying");
                }
            })
        };

        tokio::select! {
            result = crate::xds::server::spawn(self.port, config) => result,
            result = provider_task => result.map_err(From::from).and_then(|result| result),
        }
    }
}
