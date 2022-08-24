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

#[derive(clap::Args)]
pub struct Manage {
    #[clap(subcommand)]
    provider: Providers,
}

#[derive(clap::Subcommand)]
enum Providers {
    Agones {
        #[clap(
            short,
            long,
            default_value = "default",
            help = "Namespace under which the proxies run."
        )]
        config_namespace: String,
        #[clap(
            short,
            long,
            default_value = "default",
            help = "Namespace under which the game servers run."
        )]
        gameservers_namespace: String,
    },

    File {
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
