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

use crate::{
    components::relay,
    config::{Config, Providers},
};
pub use relay::Ready;

pub const PORT: u16 = 7900;

/// Runs Quilkin as a relay service that runs a Manager Discovery Service
/// (mDS) for accepting cluster and configuration information from xDS
/// management services, and exposing it as a single merged xDS service for
/// proxy services.
#[derive(clap::Args, Clone, Debug)]
pub struct Relay {
    /// Port for mDS service.
    #[clap(short, long, env = "QUILKIN_MDS_PORT", default_value_t = PORT)]
    pub mds_port: u16,
    /// Port for xDS management_server service
    #[clap(short, long, env = super::PORT_ENV_VAR, default_value_t = super::manage::PORT)]
    pub xds_port: u16,
    /// The interval in seconds at which the relay will send a discovery request
    /// to an management server after receiving no updates.
    #[clap(long, env = "QUILKIN_IDLE_REQUEST_INTERVAL_SECS")]
    pub idle_request_interval_secs: Option<u64>,
    #[clap(subcommand)]
    pub providers: Option<Providers>,
}

impl Default for Relay {
    fn default() -> Self {
        Self {
            mds_port: PORT,
            xds_port: super::manage::PORT,
            idle_request_interval_secs: None,
            providers: None,
        }
    }
}

impl Relay {
    pub async fn run(
        self,
        locality: Option<crate::net::endpoint::Locality>,
        config: Arc<Config>,
        ready: Ready,
        shutdown_rx: crate::signal::ShutdownRx,
    ) -> crate::Result<()> {
        relay::Relay {
            xds_port: self.xds_port,
            mds_port: self.mds_port,
            locality,
            provider: self.providers,
        }
        .run(crate::components::RunArgs {
            config,
            ready,
            shutdown_rx,
        })
        .await
    }
}
