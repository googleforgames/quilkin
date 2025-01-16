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
    /// The configuration source for a management server.
    #[clap(subcommand)]
    pub provider: Option<crate::config::Providers>,
    /// If specified, filters the available gameserver addresses to the one that
    /// matches the specified type
    #[clap(long)]
    pub address_type: Option<String>,
    /// If specified, additionally filters the gameserver address by its ip kind
    #[clap(long, requires("address_type"), value_enum)]
    pub ip_kind: Option<crate::config::AddrKind>,
    /// The ICAO code for the agent.
    #[clap(short, long, env, default_value_t = crate::config::IcaoCode::default())]
    pub icao_code: crate::config::IcaoCode,
}

impl clap::ValueEnum for crate::config::AddrKind {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Ipv4, Self::Ipv6, Self::Any]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        use clap::builder::PossibleValue as pv;
        Some(match self {
            Self::Ipv4 => pv::new("v4"),
            Self::Ipv6 => pv::new("v6"),
            Self::Any => pv::new("any"),
        })
    }
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            qcmp_port: PORT,
            relay: <_>::default(),
            provider: <_>::default(),
            icao_code: <_>::default(),
            address_type: None,
            ip_kind: None,
        }
    }
}

impl Agent {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        locality: Option<crate::net::endpoint::Locality>,
        config: Arc<Config>,
        ready: Ready,
        shutdown_rx: crate::ShutdownRx,
    ) -> crate::Result<()> {
        let qcmp_socket = crate::net::raw_socket_with_reuse(self.qcmp_port)?;
        let icao_code = Some(self.icao_code);

        agent::Agent {
            locality,
            qcmp_socket,
            icao_code,
            relay_servers: self.relay,
            provider: self.provider,
            address_selector: self.address_type.map(|at| crate::config::AddressSelector {
                name: at,
                kind: self.ip_kind.unwrap_or(crate::config::AddrKind::Any),
            }),
        }
        .run(crate::components::RunArgs {
            config,
            ready,
            shutdown_rx,
        })
        .await
    }
}
