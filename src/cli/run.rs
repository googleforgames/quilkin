/*
 * Copyright 2021 Google LLC
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

use std::net::SocketAddr;

#[cfg(doc)]
use crate::filters::FilterFactory;

/// Run Quilkin as a UDP reverse proxy.
#[derive(clap::Args)]
#[non_exhaustive]
pub struct Run {
    /// The port to listen on.
    #[clap(short, long, env = "QUILKIN_PORT")]
    pub port: Option<u16>,
    /// One or more socket addresses to forward packets to.
    #[clap(short, long, env = "QUILKIN_DEST")]
    pub to: Vec<SocketAddr>,
    /// One or more `quilkin manage` endpoints to listen to for config changes
    #[clap(short, long, env = "QUILKIN_MANAGEMENT_SERVER", conflicts_with("to"))]
    pub management_server: Vec<String>,
}

impl Run {
    /// Start and run a proxy.
    pub async fn run(
        &self,
        config: std::sync::Arc<crate::Config>,
        shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> crate::Result<()> {
        if let Some(port) = self.port {
            config.proxy.modify(|proxy| proxy.port = port);
        }

        if !self.to.is_empty() {
            config.clusters.modify(|clusters| {
                clusters.default_cluster_mut().localities = vec![self.to.clone().into()].into();
            });
        }

        if !self.management_server.is_empty() {
            config.management_servers.modify(|servers| {
                *servers = self
                    .management_server
                    .iter()
                    .map(ToOwned::to_owned)
                    .map(|address| crate::config::ManagementServer { address })
                    .collect();
            });
        } else if config.clusters.load().endpoints().count() == 0
            && config.management_servers.load().is_empty()
        {
            return Err(eyre::eyre!(
                "`quilkin run` requires at least one `to` address or `management_server` endpoint."
            ));
        }

        crate::Proxy::try_from(config)?.run(shutdown_rx).await
    }
}
