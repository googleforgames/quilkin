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

use crate::components::manage;
pub use manage::Ready;

define_port!(7800);

/// Runs Quilkin as a xDS management server, using `provider` as
/// a configuration source.
#[derive(clap::Args, Clone, Debug)]
pub struct Manage {
    /// One or more `quilkin relay` endpoints to push configuration changes to.
    #[clap(short, long, env = "QUILKIN_MANAGEMENT_SERVER")]
    pub relay: Vec<tonic::transport::Endpoint>,
    /// The TCP port to listen to, to serve discovery responses.
    #[clap(short, long, env = super::PORT_ENV_VAR, default_value_t = PORT)]
    pub port: u16,
    /// The configuration source for a management server.
    #[clap(subcommand)]
    pub provider: crate::config::Providers,
    /// If specified, filters the available gameserver addresses to the one that
    /// matches the specified type
    #[clap(long)]
    pub address_type: Option<String>,
    /// If specified, additionally filters the gameserver address by its ip kind
    #[clap(long, requires("address_type"), value_enum, default_value_t=crate::config::AddrKind::Any)]
    pub ip_kind: crate::config::AddrKind,
}

impl Manage {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        locality: Option<crate::net::endpoint::Locality>,
        config: std::sync::Arc<crate::Config>,
        ready: Ready,
        shutdown_rx: crate::signal::ShutdownRx,
    ) -> crate::Result<()> {
        manage::Manage {
            locality,
            port: self.port,
            provider: self.provider,
            relay_servers: self.relay,
            address_selector: self.address_type.map(|at| crate::config::AddressSelector {
                name: at,
                kind: self.ip_kind,
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
