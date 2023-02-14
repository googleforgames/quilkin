/*
 * Copyright 2023 Google LLC
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

use std::sync::Arc;

use futures::StreamExt;

use crate::config::{Config, Providers};

pub const PORT: u16 = 7900;

/// Runs Quilkin as a relay service that runs a Manager Discovery Service
/// (mDS) for accepting cluster and configuration information from xDS
/// management services, and exposing it as a single merged xDS service for
/// proxy services.
#[derive(clap::Args, Clone)]
pub struct Relay {
    /// Port for mDS service.
    #[clap(short, long, env = "QUILKIN_MDS_PORT", default_value_t = PORT)]
    mds_port: u16,
    /// Port for xDS management_server service
    #[clap(short, long, env = super::PORT_ENV_VAR, default_value_t = super::manage::PORT)]
    xds_port: u16,
    #[clap(subcommand)]
    providers: Option<Providers>,
}

impl Relay {
    pub async fn relay(&self, config: Arc<Config>) -> crate::Result<()> {
        let xds_server = crate::xds::server::spawn(self.xds_port, config.clone());
        let mds_server = tokio::spawn(crate::xds::server::control_plane_discovery_server(
            self.mds_port,
            config.clone(),
        ));

        let _provider_task = if let Some(Providers::Agones {
            config_namespace, ..
        }) = &self.providers
        {
            let config = config.clone();
            let config_namespace = config_namespace.clone();
            Some(tokio::spawn(Providers::task(move || {
                let config = config.clone();
                let config_namespace = config_namespace.clone();
                async move {
                    let client = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        kube::Client::try_default(),
                    )
                    .await??;

                    let configmap_reflector =
                        crate::config::providers::k8s::update_filters_from_configmap(
                            client.clone(),
                            config_namespace,
                            config.clone(),
                        );

                    tokio::pin!(configmap_reflector);

                    loop {
                        match configmap_reflector.next().await {
                            Some(Ok(_)) => (),
                            Some(Err(error)) => return Err(error),
                            None => break,
                        }
                    }

                    tracing::info!("configmap stream ending");
                    Ok(())
                }
            })))
        } else {
            None
        };

        tokio::select! {
            result = xds_server => {
                result
            }
            result = mds_server => {
                result?
            }
        }
    }
}
