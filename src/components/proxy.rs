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

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub use crate::{
    config::IcaoCode,
    net::{error::PipelineError, sessions::SessionPool},
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
    pub mmdb: Option<crate::net::maxmind_db::Source>,
    pub management_servers: Vec<tonic::transport::Endpoint>,
    pub to: Vec<SocketAddr>,
    pub to_tokens: Option<ToTokens>,
    pub socket: Option<socket2::Socket>,
    pub qcmp: socket2::Socket,
    pub phoenix: crate::net::TcpListener,
    pub notifier: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    pub xdp: crate::service::XdpOptions,
    pub termination_timeout: Option<crate::cli::Timeout>,
    pub filters: Option<crate::filters::FilterChain>,
    pub id: Option<String>,
}

impl Default for Proxy {
    fn default() -> Self {
        let qcmp = crate::net::raw_socket_with_reuse(0).unwrap();
        let phoenix = crate::net::TcpListener::bind(Some(crate::net::socket_port(&qcmp))).unwrap();

        Self {
            mmdb: None,
            management_servers: Vec::new(),
            to: Vec::new(),
            to_tokens: None,
            socket: Some(crate::net::raw_socket_with_reuse(0).unwrap()),
            qcmp,
            phoenix,
            notifier: None,
            xdp: Default::default(),
            termination_timeout: None,
            filters: None,
            id: None,
        }
    }
}

impl Proxy {
    pub async fn run(
        mut self,
        ready: Ready,
        mut shutdown_rx: crate::signal::ShutdownRx,
        initialized: Option<tokio::sync::oneshot::Sender<Arc<crate::Config>>>,
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

        // TODO: Remove this once the CLI is fully moved over.
        let udp_port = crate::net::socket_port(&self.socket.take().unwrap());
        let qcmp_port = crate::net::socket_port(&std::mem::replace(
            &mut self.qcmp,
            crate::net::raw_socket_with_reuse(0).unwrap(),
        ));
        let phoenix_port = std::mem::replace(
            &mut self.phoenix,
            crate::net::TcpListener::bind(None).unwrap(),
        )
        .port();

        let mut svc = crate::Service::default()
            .udp()
            .udp_port(udp_port)
            .xdp(self.xdp)
            .qcmp()
            .qcmp_port(qcmp_port)
            .phoenix()
            .phoenix_port(phoenix_port)
            .termination_timeout(self.termination_timeout);

        let config = Arc::new(svc.build_config(Default::default(), None).await?);

        if let Some(id) = self.id {
            *config.dyn_cfg.id.lock() = id;
        }

        let Some(clusters) = config.dyn_cfg.clusters() else {
            eyre::bail!("empty clusters were not created")
        };

        if !self.to.is_empty() {
            let endpoints = match &self.to_tokens {
                Some(tt) => {
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
                        let Some(filters) = config.dyn_cfg.filters() else {
                            eyre::bail!("empty filters were not created")
                        };

                        let fc = crate::filters::FilterChain::try_create([
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
                            )?,
                            crate::filters::TokenRouter::as_filter_config(None)?,
                        ])?;

                        filters.store(fc);
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
                }
                _ => self
                    .to
                    .iter()
                    .cloned()
                    .map(crate::net::endpoint::Endpoint::from)
                    .collect(),
            };

            clusters.modify(|clusters| {
                clusters.insert(None, None, endpoints);
            });
        }

        if !clusters.read().has_endpoints() && self.management_servers.is_empty() {
            return Err(eyre::eyre!(
                "`quilkin proxy` requires at least one `to` address or `management_server` endpoint."
            ));
        }

        if let Some(fc) = self.filters {
            config.dyn_cfg.filters().unwrap().store(fc);
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
                ],
            ),
        ];

        if !self.management_servers.is_empty() {
            {
                let mut lock = ready.xds_is_healthy.write();
                let check: Arc<AtomicBool> = <_>::default();
                *lock = Some(check.clone());
            }

            let id = config.id();

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
                            let xds_is_healthy =
                                ready.xds_is_healthy.read().as_ref().unwrap().clone();

                            let _stream = crate::net::xds::delta_subscribe(
                                config,
                                id,
                                management_servers,
                                xds_is_healthy.clone(),
                                tx,
                                SUBS,
                            )
                            .await
                            .map_err(|_err| eyre::eyre!("failed to acquire delta stream"))?;

                            let _ = shutdown_rx.changed().await;
                            Ok::<_, eyre::Error>(())
                        })
                    }
                })
                .expect("failed to spawn proxy-subscription thread");
        }

        let svc_task = svc.spawn_services(&config, &shutdown_rx)?;

        tracing::info!("Quilkin is ready");
        if let Some(initialized) = initialized {
            let _unused = initialized.send(config);
        }

        shutdown_rx
            .changed()
            .await
            .map_err(|error| eyre::eyre!(error))?;

        if let Ok(Err(error)) = svc_task.await {
            tracing::error!(%error, "Quilkin proxy services exited with error");
        }

        Ok(())
    }
}
