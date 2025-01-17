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
use tonic::transport::Endpoint;

#[cfg(doc)]
use crate::filters::FilterFactory;

use crate::ShutdownRx;

pub use crate::components::proxy::Ready;

/// Run Quilkin as a UDP reverse proxy.
#[derive(clap::Args, Clone, Debug, Default)]
pub struct Proxy {
    /// One or more `quilkin manage` endpoints to listen to for config changes
    #[clap(short, long, env = "QUILKIN_MANAGEMENT_SERVER", conflicts_with("to"))]
    pub management_server: Vec<Endpoint>,
    /// The remote URL or local file path to retrieve the Maxmind database.
    #[clap(long, env)]
    pub mmdb: Option<crate::net::maxmind_db::Source>,
    /// One or more socket addresses to forward packets to.
    #[clap(long, env = "QUILKIN_DEST")]
    pub to: Vec<SocketAddr>,
    /// Assigns dynamic tokens to each address in the `--to` argument
    ///
    /// Format is `<number of unique tokens>:<length of token suffix for each packet>`
    #[clap(long, env = "QUILKIN_DEST_TOKENS", requires("to"))]
    pub to_tokens: Option<String>,
}

impl Proxy {
    /// Start and run a proxy.
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        config: std::sync::Arc<crate::Config>,
        ready: Ready,
        initialized: Option<tokio::sync::oneshot::Sender<()>>,
        shutdown_rx: ShutdownRx,
    ) -> crate::Result<()> {
        tracing::info!(proxy_id = &*config.id.load(), "Starting proxy");

        let to_tokens = self
            .to_tokens
            .map(|tt| {
                let Some((count, length)) = tt.split_once(':') else {
                    eyre::bail!("--to-tokens `{tt}` is invalid, it must have a `:` separator")
                };

                let count = count.parse()?;
                let length = length.parse()?;

                Ok(crate::components::proxy::ToTokens { count, length })
            })
            .transpose()?;

        crate::components::proxy::Proxy {
            management_servers: self.management_server,
            mmdb: self.mmdb,
            to: self.to,
            to_tokens,
            notifier: None,
        }
        .run(
            crate::components::RunArgs {
                config,
                ready,
                shutdown_rx,
            },
            initialized,
        )
        .await
    }
}
