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

use crate::{components::agent, config::Config};
pub use agent::Ready;

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
    /// If specified, filters the available gameserver addresses to the one that
    /// matches
    ///
    /// This takes the form `<address_type>`, and optionally a specifier for the
    /// IP address kind following a `:` as in `<address_type>:<ipv4|ipv6>`.
    #[clap(long)]
    pub address_selector: Option<crate::config::AddressSelector>,
    /// The interval in seconds at which the agent will wait for a discovery
    /// request from a relay server before restarting the connection.
    #[clap(long, env = "QUILKIN_IDLE_REQUEST_INTERVAL_SECS")]
    pub idle_request_interval_secs: Option<u64>,
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
            idle_request_interval_secs: None,
            icao_code: <_>::default(),
            address_selector: None,
        }
    }
}

impl Agent {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        config: Arc<Config>,
        ready: Ready,
        shutdown_rx: crate::ShutdownRx,
    ) -> crate::Result<()> {
        let locality = self.region.map(|region| {
            crate::net::endpoint::Locality::new(
                region,
                self.zone.unwrap_or_default(),
                self.sub_zone.unwrap_or_default(),
            )
        });

        let qcmp_socket = crate::net::raw_socket_with_reuse(self.qcmp_port)?;
        let icao_code = Some(self.icao_code);

        agent::Agent {
            locality,
            qcmp_socket,
            icao_code,
            relay_servers: self.relay,
            provider: self.provider,
            address_selector: self.address_selector,
        }
        .run(crate::components::RunArgs {
            config,
            ready,
            shutdown_rx,
        })
        .await
    }
}
