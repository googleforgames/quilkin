/*
 * Copyright 2024 Google LLC All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

pub(crate) mod error;
pub mod packet_router;
mod sessions;

use super::RunArgs;
pub use error::PipelineError;
pub use sessions::SessionPool;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(Clone, Debug)]
pub struct Ready {
    pub idle_request_interval: std::time::Duration,
    // RwLock as this check is conditional on the proxy using xDS.
    pub xds_is_healthy: Arc<parking_lot::RwLock<Option<Arc<AtomicBool>>>>,
}

impl Default for Ready {
    fn default() -> Self {
        Self {
            idle_request_interval: crate::components::admin::IDLE_REQUEST_INTERVAL,
            xds_is_healthy: Default::default(),
        }
    }
}

impl Ready {
    #[inline]
    pub fn is_ready(&self) -> Option<bool> {
        self.xds_is_healthy
            .read()
            .as_ref()
            .map(|health| health.load(Ordering::SeqCst))
    }
}

pub struct ToTokens {
    /// The number of tokens to assign to each `to` address
    pub count: usize,
    /// The size of each token
    pub length: usize,
}

pub struct Proxy {
    pub num_workers: std::num::NonZeroUsize,
    pub mmdb: Option<crate::net::maxmind_db::Source>,
    pub management_servers: Vec<tonic::transport::Endpoint>,
    pub to: Vec<SocketAddr>,
    pub to_tokens: Option<ToTokens>,
    pub socket: Option<socket2::Socket>,
    pub qcmp: socket2::Socket,
    pub phoenix: crate::net::TcpListener,
    pub notifier: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    pub xdp: crate::cli::proxy::XdpOptions,
}

impl Default for Proxy {
    fn default() -> Self {
        let qcmp = crate::net::raw_socket_with_reuse(0).unwrap();
        let phoenix = crate::net::TcpListener::bind(Some(crate::net::socket_port(&qcmp))).unwrap();

        Self {
            num_workers: std::num::NonZeroUsize::new(1).unwrap(),
            mmdb: None,
            management_servers: Vec::new(),
            to: Vec::new(),
            to_tokens: None,
            socket: Some(crate::net::raw_socket_with_reuse(0).unwrap()),
            qcmp,
            phoenix,
            notifier: None,
            xdp: Default::default(),
        }
    }
}

impl Proxy {
    pub async fn run(
        mut self,
        RunArgs {
            config,
            ready,
            mut shutdown_rx,
        }: RunArgs<Ready>,
        initialized: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> crate::Result<()> {
        let _mmdb_task = self.mmdb.as_ref().map(|source| {
            let source = source.clone();
            tokio::spawn(async move {
                while let Err(error) =
                    tryhard::retry_fn(|| crate::MaxmindDb::update(source.clone()))
                        .retries(10)
                        .exponential_backoff(crate::config::BACKOFF_INITIAL_DELAY)
                        .await
                {
                    tracing::warn!(%error, "error updating maxmind database");
                }
            })
        });

        if !self.to.is_empty() {
            let endpoints = if let Some(tt) = &self.to_tokens {
                let (unique, overflow) = 256u64.overflowing_pow(tt.length as _);
                if overflow {
                    panic!(
                        "can't generate {} tokens of length {} maximum is {}",
                        self.to.len() * tt.count,
                        tt.length,
                        u64::MAX,
                    );
                }

                if unique < (self.to.len() * tt.count) as u64 {
                    panic!(
                        "we require {} unique tokens but only {unique} can be generated",
                        self.to.len() * tt.count,
                    );
                }

                {
                    use crate::filters::StaticFilter as _;
                    config.filters.store(Arc::new(
                        crate::filters::FilterChain::try_create([
                            crate::filters::Capture::as_filter_config(
                                crate::filters::capture::Config {
                                    metadata_key: crate::filters::capture::CAPTURED_BYTES.into(),
                                    strategy: crate::filters::capture::Strategy::Suffix(
                                        crate::filters::capture::Suffix {
                                            size: tt.length as _,
                                            remove: true,
                                        },
                                    ),
                                },
                            )
                            .unwrap(),
                            crate::filters::TokenRouter::as_filter_config(None).unwrap(),
                        ])
                        .unwrap(),
                    ));
                }

                let count = tt.count as u64;

                self.to
                    .iter()
                    .enumerate()
                    .map(|(ind, sa)| {
                        let mut tokens = std::collections::BTreeSet::new();
                        let start = ind as u64 * count;
                        for i in start..(start + count) {
                            tokens.insert(i.to_le_bytes()[..tt.length].to_vec());
                        }

                        crate::net::endpoint::Endpoint::with_metadata(
                            (*sa).into(),
                            crate::net::endpoint::Metadata { tokens },
                        )
                    })
                    .collect()
            } else {
                self.to
                    .iter()
                    .cloned()
                    .map(crate::net::endpoint::Endpoint::from)
                    .collect()
            };

            config.clusters.modify(|clusters| {
                clusters.insert(None, endpoints);
            });
        }

        if !config.clusters.read().has_endpoints() && self.management_servers.is_empty() {
            return Err(eyre::eyre!(
                 "`quilkin proxy` requires at least one `to` address or `management_server` endpoint."
             ));
        }

        #[allow(clippy::type_complexity)]
        const SUBS: &[(&str, &[(&str, Vec<String>)])] = &[
            (
                "9",
                &[
                    (crate::xds::CLUSTER_TYPE, Vec::new()),
                    (crate::xds::DATACENTER_TYPE, Vec::new()),
                    (crate::xds::FILTER_CHAIN_TYPE, Vec::new()),
                ],
            ),
            (
                "",
                &[
                    (crate::xds::CLUSTER_TYPE, Vec::new()),
                    (crate::xds::DATACENTER_TYPE, Vec::new()),
                    (crate::xds::LISTENER_TYPE, Vec::new()),
                ],
            ),
        ];

        if !self.management_servers.is_empty() {
            {
                let mut lock = ready.xds_is_healthy.write();
                let check: Arc<AtomicBool> = <_>::default();
                *lock = Some(check.clone());
            }

            let id = config.id.load();

            std::thread::Builder::new()
                .name("proxy-subscription".into())
                .spawn({
                    let config = config.clone();
                    let mut shutdown_rx = shutdown_rx.clone();
                    let management_servers = self.management_servers.clone();
                    let tx = self.notifier.clone();

                    move || {
                        let runtime = tokio::runtime::Builder::new_multi_thread()
                            .enable_all()
                            .thread_name_fn(|| {
                                static ATOMIC_ID: std::sync::atomic::AtomicUsize =
                                    std::sync::atomic::AtomicUsize::new(0);
                                let id =
                                    ATOMIC_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                format!("proxy-subscription-{id}")
                            })
                            .build()
                            .unwrap();

                        runtime.block_on(async move {
                            let client = crate::net::xds::AdsClient::connect(
                                String::clone(&id),
                                management_servers,
                            )
                            .await?;

                            let xds_is_healthy =
                                ready.xds_is_healthy.read().as_ref().unwrap().clone();

                            let _stream = client
                                .delta_subscribe(config.clone(), xds_is_healthy.clone(), tx, SUBS)
                                .await
                                .map_err(|_| eyre::eyre!("failed to acquire delta stream"))?;

                            let _ = shutdown_rx.changed().await;
                            Ok::<_, eyre::Error>(())
                        })
                    }
                })
                .expect("failed to spawn proxy-subscription thread");
        }

        let router_shutdown = self.spawn_packet_router(config.clone()).await?;
        crate::codec::qcmp::spawn(self.qcmp, shutdown_rx.clone())?;
        crate::net::phoenix::spawn(
            self.phoenix,
            config.clone(),
            shutdown_rx.clone(),
            crate::net::phoenix::Phoenix::new(crate::codec::qcmp::QcmpMeasurement::new()?),
        )?;

        tracing::info!("Quilkin is ready");
        if let Some(initialized) = initialized {
            let _ = initialized.send(());
        }

        shutdown_rx
            .changed()
            .await
            .map_err(|error| eyre::eyre!(error))?;

        (router_shutdown)(shutdown_rx);

        Ok(())
    }

    pub async fn spawn_packet_router(
        &mut self,
        config: Arc<crate::config::Config>,
    ) -> eyre::Result<Box<dyn FnOnce(crate::ShutdownRx) + Send>> {
        #[cfg(target_os = "linux")]
        {
            match self.spawn_xdp(config.clone(), self.xdp.force_xdp) {
                Ok(xdp) => {
                    return Ok(xdp);
                }
                Err(err) => {
                    if self.xdp.force_xdp {
                        return Err(err);
                    }

                    tracing::warn!(
                        ?err,
                        "failed to spawn XDP I/O loop, falling back to io-uring"
                    );
                }
            }
        }

        self.spawn_user_space_router(config).await
    }

    /// Launches the user space implementation of the packet router using
    /// sockets. This implementation uses a pool of buffers and sockets to
    /// manage UDP sessions and sockets. On Linux this will use io-uring, where
    /// as it will use epoll interfaces on non-Linux platforms.
    pub async fn spawn_user_space_router(
        &mut self,
        config: Arc<crate::config::Config>,
    ) -> eyre::Result<Box<dyn FnOnce(crate::ShutdownRx) + Send>> {
        let workers = self.num_workers.get();
        let buffer_pool = Arc::new(crate::collections::BufferPool::new(workers, 2 * 1024));

        let mut worker_sends = Vec::with_capacity(workers);
        let mut session_sends = Vec::with_capacity(workers);
        for _ in 0..workers {
            let queue = crate::net::queue(15)?;
            session_sends.push(queue.0.clone());
            worker_sends.push(queue);
        }

        let sessions = SessionPool::new(config.clone(), session_sends, buffer_pool.clone());

        packet_router::spawn_receivers(
            config,
            self.socket.take().unwrap(),
            worker_sends,
            &sessions,
            buffer_pool,
        )
        .await?;

        Ok(Box::new(move |shutdown_rx: crate::ShutdownRx| {
            sessions.shutdown(*shutdown_rx.borrow() == crate::ShutdownKind::Normal);
        }))
    }

    #[cfg(target_os = "linux")]
    fn spawn_xdp(
        &mut self,
        config: Arc<crate::config::Config>,
        force_xdp: bool,
    ) -> eyre::Result<Box<dyn FnOnce(crate::ShutdownRx) + Send>> {
        use crate::net::xdp;
        use eyre::Context as _;

        // TODO: remove this once it's been more stabilized
        if !force_xdp {
            eyre::bail!("XDP currently disabled by default");
        }

        let Some(external_port) = self.socket.as_ref().and_then(|s| {
            s.local_addr()
                .ok()
                .and_then(|la| la.as_socket().map(|sa| sa.port()))
        }) else {
            eyre::bail!("unable to determine port");
        };

        let workers = xdp::setup_xdp_io(xdp::XdpConfig {
            nic: self
                .xdp
                .network_interface
                .as_deref()
                .map_or(xdp::NicConfig::Default, xdp::NicConfig::Name),
            external_port,
            maximum_packet_memory: self.xdp.maximum_memory,
            require_zero_copy: self.xdp.force_zerocopy,
            require_tx_checksum: self.xdp.force_tx_checksum_offload,
        })
        .context("failed to setup XDP")?;

        let io_loop = xdp::spawn(workers, config).context("failed to spawn XDP I/O loop")?;
        Ok(Box::new(move |srx: crate::ShutdownRx| {
            io_loop.shutdown(*srx.borrow() == crate::ShutdownKind::Normal);
        }))
    }
}
