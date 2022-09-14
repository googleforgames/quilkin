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

/// Runs Quilkin as a xDS management server, using `provider` as
/// a configuration source.
#[derive(clap::Args)]
pub struct Manage {
    /// The configuration source for a management server.
    #[clap(subcommand)]
    pub provider: Providers,
}

/// The available xDS source providers.
#[derive(clap::Subcommand)]
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
        let provider_task = match &self.provider {
            Providers::Agones {
                gameservers_namespace,
                config_namespace,
            } => tokio::spawn(crate::config::watch::agones(
                gameservers_namespace.clone(),
                config_namespace.clone(),
                config.clone(),
            )),
            Providers::File { path } => {
                tokio::spawn(crate::config::watch::fs(config.clone(), path.clone()))
            }
        };

        tokio::select! {
            result = crate::xds::server::spawn(config) => result,
            result = provider_task => result.map_err(From::from).and_then(|result| result),
        }
    }
}
