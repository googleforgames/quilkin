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

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

use futures::FutureExt;
use tokio::{net::UdpSocket, sync::watch, time::Duration};
use tonic::transport::Endpoint;

use crate::{proxy::SessionMap, utils::net, Config, Result};

#[doc(inline)]
use crate::maxmind_db::Source;

#[cfg(doc)]
use crate::filters::FilterFactory;

const PORT: u16 = 7777;

/// Run Quilkin as a UDP reverse proxy.
#[derive(clap::Args, Clone)]
pub struct Proxy {
    /// The remote URL or local file path to retrieve the Maxmind database.
    #[clap(long, env)]
    pub mmdb: Option<Source>,
    /// The port to listen on.
    #[clap(short, long, env = super::PORT_ENV_VAR, default_value_t = PORT)]
    pub port: u16,
    /// One or more socket addresses to forward packets to.
    #[clap(short, long, env = "QUILKIN_DEST", conflicts_with("provider"))]
    pub to: Vec<SocketAddr>,
    /// One or more socket addresses to forward packets to.
    #[clap(subcommand)]
    pub provider: Option<Providers>,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            mmdb: <_>::default(),
            port: PORT,
            to: <_>::default(),
            provider: <_>::default(),
        }
    }
}

impl Proxy {
    /// Start and run a proxy.
    pub async fn run(
        &self,
        config: Arc<crate::Config>,
        mut shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> crate::Result<()> {
        const SESSION_TIMEOUT_SECONDS: Duration = Duration::from_secs(60);
        const SESSION_EXPIRY_POLL_INTERVAL: Duration = Duration::from_secs(60);

        let _mmdb_task = self.mmdb.clone().map(|source| {
            tokio::spawn(async move {
                use crate::config::BACKOFF_INITIAL_DELAY_MILLISECONDS;
                while let Err(error) =
                    tryhard::retry_fn(|| crate::MaxmindDb::update(source.clone()))
                        .retries(10)
                        .exponential_backoff(std::time::Duration::from_millis(
                            BACKOFF_INITIAL_DELAY_MILLISECONDS,
                        ))
                        .await
                {
                    tracing::warn!(%error, "error updating maxmind database");
                }
            })
        });

        if !self.to.is_empty() {
            config.clusters.modify(|clusters| {
                clusters.default_cluster_mut().localities = vec![self.to.clone().into()].into();
            });
        }

        if self.provider.is_none() && config.clusters.load().endpoints().count() == 0 {
            return Err(eyre::eyre!(
                "`quilkin proxy` requires at least one `to` address or a configuration discovery provider."
            ));
        }

        let id = config.id.load();
        tracing::info!(port = self.port, proxy_id = &*id, "Starting");

        let sessions =
            crate::proxy::SessionMap::new(SESSION_TIMEOUT_SECONDS, SESSION_EXPIRY_POLL_INTERVAL);
        self.run_recv_from(&config, sessions, shutdown_rx.clone())?;
        tracing::info!("Quilkin is ready");

        match self.run_discovery_provider_task(&config) {
            Some(provider_task) => tokio::select! {
                result = provider_task => result.map(drop),
                result = shutdown_rx.changed() => result.map_err(|error| eyre::eyre!(error)),
            },
            None => shutdown_rx
                .changed()
                .await
                .map_err(|error| eyre::eyre!(error)),
        }
    }

    /// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
    /// Each received packet is placed on a queue to be processed by a worker task.
    /// This function also spawns the set of worker tasks responsible for consuming packets
    /// off the aforementioned queue and processing them through the filter chain and session
    /// pipeline.
    fn run_recv_from(
        &self,
        config: &Arc<Config>,
        sessions: SessionMap,
        shutdown_rx: watch::Receiver<()>,
    ) -> Result<()> {
        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = num_cpus::get();

        // Contains config for each worker task.
        let mut workers = Vec::with_capacity(num_workers);
        for worker_id in 0..num_workers {
            let socket = Arc::new(self.bind(self.port)?);
            workers.push(crate::proxy::DownstreamReceiveWorkerConfig {
                worker_id,
                socket: socket.clone(),
                shutdown_rx: shutdown_rx.clone(),
                config: config.clone(),
                sessions: sessions.clone(),
            })
        }

        // Start the worker tasks that pick up received packets from their queue
        // and processes them.
        for worker in workers {
            worker.spawn();
        }

        Ok(())
    }

    /// binds the local configured port with port and address reuse applied.
    fn bind(&self, port: u16) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        net::socket_with_reuse(addr.into())
    }

    /// Runs a configuration discovery task based on what provider is given.
    fn run_discovery_provider_task(
        &self,
        config: &Arc<crate::Config>,
    ) -> Option<impl Future<Output = crate::Result<ProviderResult>>> {
        match &self.provider {
            Some(Providers::Xds { management_server }) => {
                Some(Self::run_xds_discovery(config.clone(), management_server.clone()).boxed())
            }
            Some(Providers::Agones(args)) => Some(Self::run_agones_discovery(config, args).boxed()),
            None => None,
        }
    }

    /// Starts the xDS configuration discovery task that will update `config`
    /// based on changes provided to the client.
    async fn run_xds_discovery(
        config: Arc<crate::Config>,
        management_servers: Vec<Endpoint>,
    ) -> crate::Result<ProviderResult> {
        let client =
            crate::xds::Client::connect(String::clone(&config.id.load()), management_servers)
                .await?;
        let mut stream = client
            .stream(move |resource| config.apply(resource))
            .await?;

        tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
        stream.send(crate::xds::ResourceType::Endpoint, &[]).await?;
        tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
        stream.send(crate::xds::ResourceType::Listener, &[]).await?;

        Ok(ProviderResult::Xds(client, stream))
    }

    /// Runs a Agones/Kubernetes configuration discovery task.
    fn run_agones_discovery(
        config: &Arc<crate::Config>,
        args: &crate::cli::Kubernetes,
    ) -> impl Future<Output = Result<ProviderResult>> {
        let config = config.clone();
        let gsn = args.gameservers_namespace.clone();
        let cn = args.config_namespace.clone();

        crate::task::provider(move || {
            crate::config::watch::agones(gsn.clone(), cn.clone(), None, config.clone())
                .map(|result| result.map(|_| ProviderResult::Agones))
        })
    }
}

#[non_exhaustive]
pub enum ProviderResult {
    Xds(crate::xds::Client, crate::xds::client::Stream),
    Agones,
}

#[derive(Debug, Clone, clap::Subcommand)]
#[non_exhaustive]
pub enum Providers {
    Agones(crate::cli::Kubernetes),
    /// Listens to the provided management endpoint(s) for configuration changes.
    Xds {
        /// The list of endpoints to connect to, Quilkin will connect to the
        /// first successful endpoint.
        #[clap(short, long, env = "QUILKIN_MANAGEMENT_SERVER")]
        management_server: Vec<Endpoint>,
    },
}
