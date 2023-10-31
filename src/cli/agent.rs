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

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use super::Admin;
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
    /// The interval in seconds at which the agent will wait for a discovery
    /// request from a relay server before restarting the connection.
    #[clap(long, env = "QUILKIN_IDLE_REQUEST_INTERVAL_SECS", default_value_t = super::admin::IDLE_REQUEST_INTERVAL_SECS)]
    pub idle_request_interval_secs: u64,
    /// The ICAO code for the agent.
    #[clap(short, long, env, default_value_t = crate::config::IcaoCode::default())]
    pub icao_code: crate::config::IcaoCode,
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
            idle_request_interval_secs: super::admin::IDLE_REQUEST_INTERVAL_SECS,
            icao_code: <_>::default(),
        }
    }
}

impl Agent {
    pub async fn run(
        &self,
        config: Arc<Config>,
        mode: Admin,
        mut shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> crate::Result<()> {
        let locality = (self.region.is_some() || self.zone.is_some() || self.sub_zone.is_some())
            .then(|| crate::net::endpoint::Locality {
                region: self.region.clone().unwrap_or_default(),
                zone: self.zone.clone().unwrap_or_default(),
                sub_zone: self.sub_zone.clone().unwrap_or_default(),
            });

        config.qcmp_port.store(self.qcmp_port.into());
        config.icao_code.store(self.icao_code.clone().into());

        let runtime_config = mode.unwrap_agent();

        if !self.relay.is_empty() {
            match self.provider.as_ref() {
                Some(provider) => {
                    let config = config.clone();
                    let provider_is_healthy = runtime_config.provider_is_healthy.clone();
                    let locality = locality.clone();
                    let provider = provider.clone();
                    let mut shutdown_rx = shutdown_rx.clone();
                    std::thread::spawn(move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap();

                        runtime
                            .block_on(async move {
                                let provider_task =
                                    provider.spawn(config, provider_is_healthy.clone(), locality);

                                tokio::select! {
                                    result = provider_task => result,
                                    _ = shutdown_rx.changed() => Ok(Ok(())),
                                }
                            })
                            .unwrap()
                            .unwrap();
                    });
                }
                None => return Err(eyre::eyre!("no configuration provider given")),
            };

            let relay = self.relay.clone();
            let config = config.clone();
            let mode = mode.clone();
            let mut shutdown_rx = shutdown_rx.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                runtime
                    .block_on(async move {
                        let client = crate::net::xds::client::MdsClient::connect(
                            String::clone(&config.id.load()),
                            mode.clone(),
                            relay.clone(),
                        )
                        .await
                        .unwrap();

                        let _stream = client.mds_client_stream(config);

                        shutdown_rx.changed().await
                    })
                    .unwrap();
            });
        }

        crate::codec::qcmp::spawn(self.qcmp_port, shutdown_rx.clone())?;
        shutdown_rx.changed().await.map_err(From::from)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeConfig {
    pub idle_request_interval_secs: u64,
    pub provider_is_healthy: Arc<AtomicBool>,
    pub relay_is_healthy: Arc<AtomicBool>,
}

impl RuntimeConfig {
    pub fn is_ready(&self) -> bool {
        self.provider_is_healthy.load(Ordering::SeqCst)
            && self.relay_is_healthy.load(Ordering::SeqCst)
    }
}
