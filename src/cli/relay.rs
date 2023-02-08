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
}

impl Relay {
    pub async fn relay(&self, config: Arc<Config>) -> crate::Result<()> {
        let xds_server = crate::xds::server::spawn(self.xds_port, config.clone());
        let mds_server = tokio::spawn(crate::xds::server::control_plane_discovery_server(
            self.mds_port,
            config,
        ));

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
