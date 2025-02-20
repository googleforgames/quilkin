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

use super::RunArgs;
use crate::config::{IcaoCode, Providers};
pub use crate::net::{endpoint::Locality, DualStackLocalSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Debug, Default)]
pub struct Ready {
    pub provider_is_healthy: Arc<AtomicBool>,
    pub relay_is_healthy: Arc<AtomicBool>,
    /// If true, only care about the provider being healthy, not the relay
    pub is_manage: bool,
}

impl Ready {
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.provider_is_healthy.load(Ordering::SeqCst)
            && (self.is_manage || self.relay_is_healthy.load(Ordering::SeqCst))
    }
}

pub struct Agent {
    pub locality: Option<Locality>,
    pub port: u16,
    pub icao_code: Option<IcaoCode>,
    pub relay_servers: Vec<tonic::transport::Endpoint>,
    pub provider: Option<Providers>,
    pub address_selector: Option<crate::config::AddressSelector>,
}

impl Agent {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        RunArgs {
            config,
            ready,
            mut shutdown_rx,
        }: RunArgs<Ready>,
    ) -> crate::Result<()> {
        {
            let crate::config::DatacenterConfig::Agent {
                icao_code,
                qcmp_port,
            } = &config.datacenter
            else {
                unreachable!("this should be an agent config");
            };

            qcmp_port.store(self.port.into());
            icao_code.store(self.icao_code.unwrap_or_default().into());
        }

        let _mds_task = if !self.relay_servers.is_empty() {
            let Some(provider) = self.provider else {
                return Err(eyre::eyre!("no configuration provider given"));
            };

            let _provider_task = match provider {
                Providers::Agones {
                    gameservers_namespace,
                    ..
                } => crate::config::providersv2::Providers::default()
                    .agones()
                    .agones_namespace(gameservers_namespace),

                Providers::File { path } => crate::config::providersv2::Providers::default()
                    .fs()
                    .fs_path(path),
            }
            .spawn_providers(&config, ready.provider_is_healthy.clone(), self.locality);

            let task = crate::net::xds::client::MdsClient::connect(config.id(), self.relay_servers);

            tokio::select! {
                result = task => {
                    let client = result?;

                    // Attempt to connect to a delta stream if the relay has one
                    // available, otherwise fallback to the regular aggregated stream
                    Some(client.delta_stream(config.clone(), ready.relay_is_healthy.clone()).await.map_err(|_| eyre::eyre!("failed to acquire delta stream"))?)
                }
                _ = shutdown_rx.changed() => return Ok(()),
            }
        } else {
            tracing::info!("no relay servers given");
            None
        };

        crate::cli::Service::default()
            .qcmp()
            .qcmp_port(self.port)
            .spawn_services(&config, &shutdown_rx)?;
        shutdown_rx.changed().await.map_err(From::from)
    }
}
