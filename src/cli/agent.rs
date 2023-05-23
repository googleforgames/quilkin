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

use crate::config::Config;

define_port!(7600);

/// Runs Quilkin as a relay service that runs a Manager Discovery Service
/// (mDS) for accepting cluster and configuration information from xDS
/// management services, and exposing it as a single merged xDS service for
/// proxy services.
#[derive(clap::Args, Clone, Debug)]
pub struct Agent {
    /// Port for QCMP service.
    #[clap(short, long, env = "QCMP_PORT", default_value_t = PORT)]
    pub qcmp_port: u16,
    /// One or more `quilkin relay` endpoints to push configuration changes to.
    #[clap(short, long, env = "QUILKIN_MANAGEMENT_SERVER")]
    pub relay: Vec<tonic::transport::Endpoint>,
    /// The `region` to set in the cluster map for any provider
    /// endpoints discovered.
    #[clap(long, env = "QUILKIN_REGION")]
    pub region: Option<String>,
    /// The `zone` in the `region` to set in the cluster map for any provider
    /// endpoints discovered.
    #[clap(long, env = "QUILKIN_ZONE")]
    pub zone: Option<String>,
    /// The `sub_zone` in the `zone` in the `region` to set in the cluster map
    /// for any provider endpoints discovered.
    #[clap(long, env = "QUILKIN_SUB_ZONE")]
    pub sub_zone: Option<String>,
    /// The configuration source for a management server.
    #[clap(subcommand)]
    pub provider: Option<crate::config::Providers>,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            qcmp_port: PORT,
            relay: <_>::default(),
            region: <_>::default(),
            zone: <_>::default(),
            sub_zone: <_>::default(),
            provider: <_>::default(),
        }
    }
}

impl Agent {
    pub async fn run(
        &self,
        config: Arc<Config>,
        mut shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> crate::Result<()> {
        let locality = (self.region.is_some() || self.zone.is_some() || self.sub_zone.is_some())
            .then(|| crate::endpoint::Locality {
                region: self.region.clone().unwrap_or_default(),
                zone: self.zone.clone().unwrap_or_default(),
                sub_zone: self.sub_zone.clone().unwrap_or_default(),
            });

        let _mds_task = if !self.relay.is_empty() {
            let _provider_task = match self.provider.as_ref() {
                Some(provider) => Some(provider.spawn(config.clone(), locality.clone())),
                None => return Err(eyre::eyre!("no configuration provider given")),
            };

            let task = crate::xds::client::MdsClient::connect(
                String::clone(&config.id.load()),
                self.relay.clone(),
            );

            tokio::select! {
                result = task => Some(result?.mds_client_stream(config.clone())),
                _ = shutdown_rx.changed() => return Ok(()),
            }
        } else {
            tracing::info!("no relay servers given");
            None
        };

        let _qcmp_task = crate::protocol::spawn(self.qcmp_port).await?;

        shutdown_rx.changed().await.map_err(From::from)
    }
}
