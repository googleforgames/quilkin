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
    pub provider: crate::config::Providers,
}

impl Manage {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        config: std::sync::Arc<crate::Config>,
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

        let listener = crate::net::TcpListener::bind(Some(self.port))?;

        manage::Manage {
            locality,
            provider: self.provider,
            relay_servers: self.relay,
            listener,
        }
        .run(crate::components::RunArgs {
            config,
            ready,
            shutdown_rx,
        })
        .await
    }
}
