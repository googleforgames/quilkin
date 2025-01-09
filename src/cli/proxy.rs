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

define_port!(7777);

const QCMP_PORT: u16 = 7600;

/// Run Quilkin as a UDP reverse proxy.
#[derive(clap::Args, Clone, Debug)]
pub struct Proxy {
    /// One or more `quilkin manage` endpoints to listen to for config changes
    #[clap(short, long, env = "QUILKIN_MANAGEMENT_SERVER", conflicts_with("to"))]
    pub management_server: Vec<Endpoint>,
    /// The remote URL or local file path to retrieve the Maxmind database.
    #[clap(long, env)]
    pub mmdb: Option<crate::net::maxmind_db::Source>,
    /// The port to listen on.
    #[clap(short, long, env = super::PORT_ENV_VAR, default_value_t = PORT)]
    pub port: u16,
    /// The port to listen on.
    #[clap(short, long, env = "QUILKIN_QCMP_PORT", default_value_t = QCMP_PORT)]
    pub qcmp_port: u16,
    /// One or more socket addresses to forward packets to.
    #[clap(long, env = "QUILKIN_DEST")]
    pub to: Vec<SocketAddr>,
    /// Assigns dynamic tokens to each address in the `--to` argument
    ///
    /// Format is `<number of unique tokens>:<length of token suffix for each packet>`
    #[clap(long, env = "QUILKIN_DEST_TOKENS", requires("to"))]
    pub to_tokens: Option<String>,
    /// The interval in seconds at which the relay will send a discovery request
    /// to an management server after receiving no updates.
    #[clap(long, env = "QUILKIN_IDLE_REQUEST_INTERVAL_SECS")]
    pub idle_request_interval_secs: Option<u64>,
    /// Number of worker threads used to process packets. If not specified defaults
    /// to number of cpus.
    #[clap(short, long, env = "QUILKIN_WORKERS")]
    pub workers: Option<std::num::NonZeroUsize>,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            management_server: <_>::default(),
            mmdb: <_>::default(),
            port: PORT,
            qcmp_port: QCMP_PORT,
            to: <_>::default(),
            to_tokens: None,
            idle_request_interval_secs: None,
            workers: None,
        }
    }
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
        tracing::info!(
            port = self.port,
            proxy_id = &*config.id.load(),
            "Starting proxy"
        );

        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = self.workers.unwrap_or_else(|| {
            std::num::NonZeroUsize::new(num_cpus::get())
                .expect("num_cpus returned 0, which should be impossible")
        });

        let socket = crate::net::raw_socket_with_reuse(self.port)?;
        let qcmp = crate::net::raw_socket_with_reuse(self.qcmp_port)?;
        let phoenix = crate::net::TcpListener::bind(Some(self.qcmp_port))?;

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
            num_workers,
            socket: Some(socket),
            qcmp,
            phoenix,
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
