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

mod error;
pub mod packet_router;
mod sessions;

#[cfg(target_os = "linux")]
pub(crate) mod io_uring_shared;

use super::RunArgs;
pub use error::{ErrorMap, PipelineError};
pub use sessions::SessionPool;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub struct SendPacket {
    pub destination: SocketAddr,
    pub data: crate::pool::FrozenPoolBuffer,
    pub asn_info: Option<crate::net::maxmind_db::MetricsIpNetEntry>,
}

pub struct RecvPacket {
    pub source: SocketAddr,
    pub data: crate::pool::PoolBuffer,
}

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
    pub socket: socket2::Socket,
    pub qcmp: socket2::Socket,
    pub phoenix: crate::net::TcpListener,
    pub notifier: Option<tokio::sync::mpsc::UnboundedSender<String>>,
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
            socket: crate::net::raw_socket_with_reuse(0).unwrap(),
            qcmp,
            phoenix,
            notifier: None,
        }
    }
}

impl Proxy {
    pub async fn run(
        self,
        RunArgs {
            config,
            ready,
            mut shutdown_rx,
        }: RunArgs<Ready>,
        initialized: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> crate::Result<()> {
        let _mmdb_task = self.mmdb.map(|source| {
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
            let endpoints = if let Some(tt) = self.to_tokens {
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

        let id = config.id.load();
        let num_workers = self.num_workers.get();

        let (upstream_sender, upstream_receiver) = async_channel::bounded(250);
        let buffer_pool = Arc::new(crate::pool::BufferPool::new(num_workers, 64 * 1024));
        let sessions = SessionPool::new(
            config.clone(),
            upstream_sender,
            buffer_pool.clone(),
            shutdown_rx.clone(),
        );

        if !self.management_servers.is_empty() {
            {
                let mut lock = ready.xds_is_healthy.write();
                let check: Arc<AtomicBool> = <_>::default();
                *lock = Some(check.clone());
            }

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
                                .delta_subscribe(
                                    config.clone(),
                                    xds_is_healthy.clone(),
                                    tx,
                                    [
                                        (crate::xds::CLUSTER_TYPE, Vec::new()),
                                        (crate::xds::DATACENTER_TYPE, Vec::new()),
                                        (crate::xds::FILTER_CHAIN_TYPE, Vec::new()),
                                    ],
                                )
                                .await
                                .map_err(|_| eyre::eyre!("failed to acquire delta stream"))?;

                            let _ = shutdown_rx.changed().await;
                            Ok::<_, eyre::Error>(())
                        })
                    }
                })
                .expect("failed to spawn proxy-subscription thread");
        }

        let worker_notifications = packet_router::spawn_receivers(
            config.clone(),
            self.socket,
            num_workers,
            &sessions,
            upstream_receiver,
            buffer_pool,
            shutdown_rx.clone(),
        )
        .await?;

        crate::codec::qcmp::spawn(self.qcmp, shutdown_rx.clone())?;
        crate::net::phoenix::spawn(
            self.phoenix,
            config.clone(),
            shutdown_rx.clone(),
            crate::net::phoenix::Phoenix::new(crate::codec::qcmp::QcmpMeasurement::new()?),
        )?;

        for notification in worker_notifications {
            let _ = notification.await;
        }

        tracing::info!("Quilkin is ready");
        if let Some(initialized) = initialized {
            let _ = initialized.send(());
        }

        shutdown_rx
            .changed()
            .await
            .map_err(|error| eyre::eyre!(error))?;

        if *shutdown_rx.borrow() == crate::ShutdownKind::Normal {
            tracing::info!(sessions=%sessions.sessions().len(), "waiting for active sessions to expire");

            let interval = std::time::Duration::from_millis(100);

            while sessions.sessions().is_not_empty() {
                tokio::time::sleep(interval).await;
                tracing::debug!(sessions=%sessions.sessions().len(), "sessions still active");
            }
            tracing::info!("all sessions expired");
        }

        Ok(())
    }
}
