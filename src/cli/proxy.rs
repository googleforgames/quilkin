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

mod sessions;

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::mpsc;
use tonic::transport::Endpoint;

use super::Admin;
use sessions::{DownstreamReceiver, SessionKey, SessionPool};

#[cfg(doc)]
use crate::filters::FilterFactory;

use crate::{
    filters::{Filter, ReadContext},
    net::{maxmind_db::IpNetEntry, xds::ResourceType, DualStackLocalSocket},
    pool::PoolBuffer,
    Config, Result, ShutdownRx,
};

use eyre::WrapErr as _;

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
    #[clap(short, long, env = "QUILKIN_DEST")]
    pub to: Vec<SocketAddr>,
    /// The interval in seconds at which the relay will send a discovery request
    /// to an management server after receiving no updates.
    #[clap(long, env = "QUILKIN_IDLE_REQUEST_INTERVAL_SECS", default_value_t = super::admin::idle_request_interval_secs())]
    pub idle_request_interval_secs: u64,
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
            idle_request_interval_secs: super::admin::idle_request_interval_secs(),
            workers: None,
        }
    }
}

impl Proxy {
    /// Start and run a proxy.
    #[tracing::instrument(skip_all)]
    pub async fn run(
        &self,
        config: std::sync::Arc<crate::Config>,
        mode: Admin,
        initialized: Option<tokio::sync::oneshot::Sender<u16>>,
        mut shutdown_rx: ShutdownRx,
    ) -> crate::Result<()> {
        let _mmdb_task = self.mmdb.clone().map(|source| {
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
            config.clusters.modify(|clusters| {
                clusters.insert(
                    None,
                    self.to
                        .iter()
                        .cloned()
                        .map(crate::net::endpoint::Endpoint::from)
                        .collect(),
                );
            });
        }

        if !config.clusters.read().has_endpoints() && self.management_server.is_empty() {
            return Err(eyre::eyre!(
                 "`quilkin proxy` requires at least one `to` address or `management_server` endpoint."
             ));
        }

        let id = config.id.load();
        tracing::info!(port = self.port, proxy_id = &*id, "Starting");

        let runtime_config = mode.unwrap_proxy();

        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = self
            .workers
            .map(|nz| nz.get())
            .unwrap_or_else(num_cpus::get);

        eyre::ensure!(num_workers > 0, "must use at least 1 worker");

        let (upstream_sender, upstream_receiver) =
            async_channel::bounded::<(PoolBuffer, Option<IpNetEntry>, SocketAddr)>(250);
        let buffer_pool = Arc::new(crate::pool::BufferPool::new(num_workers, 64 * 1024));
        let sessions = SessionPool::new(
            config.clone(),
            upstream_sender,
            buffer_pool.clone(),
            shutdown_rx.clone(),
        );

        if !self.management_server.is_empty() {
            {
                let mut lock = runtime_config.xds_is_healthy.write();
                let check: Arc<AtomicBool> = <_>::default();
                *lock = Some(check.clone());
            }

            std::thread::spawn({
                let config = config.clone();
                let mut shutdown_rx = shutdown_rx.clone();
                let idle_request_interval = Duration::from_secs(self.idle_request_interval_secs);
                let management_server = self.management_server.clone();
                let mode = mode.clone();
                move || {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .unwrap();

                    runtime.block_on(async move {
                        let client = crate::net::xds::AdsClient::connect(
                            String::clone(&id),
                            mode,
                            management_server,
                        )
                        .await?;

                        let mut delta_sub = None;
                        let mut state_sub = None;

                        match client
                            .delta_subscribe(
                                config.clone(),
                                idle_request_interval,
                                [
                                    (ResourceType::Cluster, Vec::new()),
                                    (ResourceType::Listener, Vec::new()),
                                    (ResourceType::Datacenter, Vec::new()),
                                ],
                            )
                            .await
                        {
                            Ok(ds) => delta_sub = Some(ds),
                            Err(client) => {
                                let mut stream =
                                    client.xds_client_stream(config, idle_request_interval);

                                tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
                                stream
                                    .aggregated_subscribe(ResourceType::Cluster, &[])
                                    .await?;
                                tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
                                stream
                                    .aggregated_subscribe(ResourceType::Listener, &[])
                                    .await?;
                                tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
                                stream
                                    .aggregated_subscribe(ResourceType::Datacenter, &[])
                                    .await?;

                                state_sub = Some(stream);
                            }
                        }

                        let _ = shutdown_rx.changed().await;
                        drop(delta_sub);
                        drop(state_sub);
                        Ok::<_, eyre::Error>(())
                    })
                }
            });
        }

        // Generally only for testing purposes, if port is 0 we bind to an ephemeral
        // port and return that to the caller
        let port = if self.port == 0 {
            let ds = DualStackLocalSocket::new(0).wrap_err("failed to allocate ephemeral port")?;
            let addr = ds
                .local_ipv6_addr()
                .wrap_err("failed to retrieve IPv6 ephemeral port")?;

            addr.port()
        } else {
            self.port
        };

        let worker_notifications = self.run_recv_from(
            &config,
            port,
            num_workers,
            &sessions,
            upstream_receiver,
            buffer_pool,
        )?;

        crate::codec::qcmp::spawn(self.qcmp_port).await?;
        for notification in worker_notifications {
            notification.notified().await;
        }

        tracing::info!("Quilkin is ready");
        if let Some(initialized) = initialized {
            let _ = initialized.send(port);
        }

        shutdown_rx
            .changed()
            .await
            .map_err(|error| eyre::eyre!(error))?;

        if *shutdown_rx.borrow() == crate::ShutdownKind::Normal {
            tracing::info!(sessions=%sessions.sessions().len(), "waiting for active sessions to expire");
            while sessions.sessions().is_not_empty() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                tracing::debug!(sessions=%sessions.sessions().len(), "sessions still active");
            }
            tracing::info!("all sessions expired");
        }

        Ok(())
    }

    /// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
    /// Each received packet is placed on a queue to be processed by a worker task.
    /// This function also spawns the set of worker tasks responsible for consuming packets
    /// off the aforementioned queue and processing them through the filter chain and session
    /// pipeline.
    fn run_recv_from(
        &self,
        config: &Arc<Config>,
        port: u16,
        num_workers: usize,
        sessions: &Arc<SessionPool>,
        upstream_receiver: DownstreamReceiver,
        buffer_pool: Arc<crate::pool::BufferPool>,
    ) -> Result<Vec<Arc<tokio::sync::Notify>>> {
        let (error_sender, mut error_receiver) = mpsc::unbounded_channel();

        let worker_notifications = (0..num_workers)
            .map(|worker_id| {
                let worker = DownstreamReceiveWorkerConfig {
                    worker_id,
                    upstream_receiver: upstream_receiver.clone(),
                    port,
                    config: config.clone(),
                    sessions: sessions.clone(),
                    error_sender: error_sender.clone(),
                    buffer_pool: buffer_pool.clone(),
                };

                worker.spawn()
            })
            .collect();

        tokio::spawn(async move {
            let mut log_task = tokio::time::interval(std::time::Duration::from_secs(5));

            let mut pipeline_errors = std::collections::HashMap::<String, u64>::new();
            loop {
                tokio::select! {
                    _ = log_task.tick() => {
                        for (error, instances) in &pipeline_errors {
                            tracing::warn!(%error, %instances, "pipeline report");
                        }
                        pipeline_errors.clear();
                    }
                    received = error_receiver.recv() => {
                        let Some(error) = received else {
                            tracing::info!("pipeline reporting task closed");
                            return;
                        };

                        let entry = pipeline_errors.entry(error.to_string()).or_default();
                        *entry += 1;
                    }
                }
            }
        });

        Ok(worker_notifications)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeConfig {
    pub idle_request_interval: std::time::Duration,
    // RwLock as this check is conditional on the proxy using xDS.
    pub xds_is_healthy: Arc<parking_lot::RwLock<Option<Arc<AtomicBool>>>>,
}

impl RuntimeConfig {
    pub fn is_ready(&self, config: &Config) -> bool {
        self.xds_is_healthy
            .read()
            .as_ref()
            .map_or(config.clusters.read().has_endpoints(), |health| {
                health.load(Ordering::SeqCst)
            })
    }
}

/// Packet received from local port
#[derive(Debug)]
struct DownstreamPacket {
    asn_info: Option<crate::net::maxmind_db::IpNetEntry>,
    contents: PoolBuffer,
    received_at: i64,
    source: SocketAddr,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub(crate) struct DownstreamReceiveWorkerConfig {
    /// ID of the worker.
    pub worker_id: usize,
    /// Socket with reused port from which the worker receives packets.
    pub upstream_receiver: DownstreamReceiver,
    pub port: u16,
    pub config: Arc<Config>,
    pub sessions: Arc<SessionPool>,
    pub error_sender: mpsc::UnboundedSender<PipelineError>,
    pub buffer_pool: Arc<crate::pool::BufferPool>,
}

impl DownstreamReceiveWorkerConfig {
    pub fn spawn(self) -> Arc<tokio::sync::Notify> {
        let Self {
            worker_id,
            upstream_receiver,
            port,
            config,
            sessions,
            error_sender,
            buffer_pool,
        } = self;

        let notify = Arc::new(tokio::sync::Notify::new());
        let is_ready = notify.clone();

        uring_spawn!(async move {
            // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
            // packet, which is the maximum value of 16 a bit integer.
            let mut last_received_at = None;
            let socket = DualStackLocalSocket::new(port).unwrap().make_refcnt();
            let send_socket = socket.clone();

            uring_inner_spawn!(async move {
                is_ready.notify_one();
                loop {
                    tokio::select! {
                        result = upstream_receiver.recv() => {
                            match result {
                                Err(error) => {
                                    tracing::trace!(%error, "error receiving packet");
                                    crate::metrics::errors_total(
                                        crate::metrics::WRITE,
                                        &error.to_string(),
                                        None,
                                        )
                                        .inc();
                                }
                                Ok((data, asn_info, send_addr)) => {
                                    let (result, _) = send_socket.send_to(data, send_addr).await;
                                    let asn_info = asn_info.as_ref();
                                    match result {
                                        Ok(size) => {
                                            crate::metrics::packets_total(crate::metrics::WRITE, asn_info)
                                                .inc();
                                            crate::metrics::bytes_total(crate::metrics::WRITE, asn_info)
                                                .inc_by(size as u64);
                                        }
                                        Err(error) => {
                                            let source = error.to_string();
                                            crate::metrics::errors_total(
                                                crate::metrics::WRITE,
                                                &source,
                                                asn_info,
                                                )
                                                .inc();
                                            crate::metrics::packets_dropped_total(
                                                crate::metrics::WRITE,
                                                &source,
                                                asn_info,
                                                )
                                                .inc();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });

            loop {
                let buffer = buffer_pool.clone().alloc();

                let (result, contents) = socket.recv_from(buffer).await;
                match result {
                    Ok((_size, mut source)) => {
                        crate::net::to_canonical(&mut source);
                        let packet = DownstreamPacket {
                            received_at: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
                            asn_info: crate::net::maxmind_db::MaxmindDb::lookup(source.ip()),
                            contents,
                            source,
                        };

                        if let Some(last_received_at) = last_received_at {
                            crate::metrics::packet_jitter(
                                crate::metrics::READ,
                                packet.asn_info.as_ref(),
                            )
                            .set(packet.received_at - last_received_at);
                        }
                        last_received_at = Some(packet.received_at);

                        Self::process_task(
                            packet,
                            source,
                            worker_id,
                            &config,
                            &sessions,
                            &error_sender,
                        )
                        .await;
                    }
                    Err(error) => {
                        tracing::error!(%error, "error receiving packet");
                        return;
                    }
                }
            }
        });

        notify
    }

    #[inline]
    async fn process_task(
        packet: DownstreamPacket,
        source: std::net::SocketAddr,
        worker_id: usize,
        config: &Arc<Config>,
        sessions: &Arc<SessionPool>,
        error_sender: &mpsc::UnboundedSender<PipelineError>,
    ) {
        tracing::trace!(
            id = worker_id,
            size = packet.contents.len(),
            source = %source,
            "received packet from downstream"
        );

        let timer = crate::metrics::processing_time(crate::metrics::READ).start_timer();
        let asn_info = packet.asn_info.clone();
        let asn_info = asn_info.as_ref();
        match Self::process_downstream_received_packet(packet, config, sessions).await {
            Ok(()) => {}
            Err(error) => {
                let discriminant = PipelineErrorDiscriminants::from(&error).to_string();
                crate::metrics::errors_total(crate::metrics::READ, &discriminant, asn_info).inc();
                crate::metrics::packets_dropped_total(
                    crate::metrics::READ,
                    &discriminant,
                    asn_info,
                )
                .inc();
                let _ = error_sender.send(error);
            }
        }

        timer.stop_and_record();
    }

    /// Processes a packet by running it through the filter chain.
    #[inline]
    async fn process_downstream_received_packet(
        packet: DownstreamPacket,
        config: &Arc<Config>,
        sessions: &Arc<SessionPool>,
    ) -> Result<(), PipelineError> {
        if !config.clusters.read().has_endpoints() {
            tracing::trace!("no upstream endpoints");
            return Err(PipelineError::NoUpstreamEndpoints);
        }

        let filters = config.filters.load();
        let mut context = ReadContext::new(
            config.clusters.clone_value(),
            packet.source.into(),
            packet.contents,
        );
        filters.read(&mut context).await?;

        let ReadContext {
            destinations,
            contents,
            ..
        } = context;

        // Similar to bytes::BytesMut::freeze, we turn the mutable pool buffer
        // into an immutable one with its own internal arc so it can be cloned
        // cheaply and returned to the pool once all references are dropped
        let contents = contents.freeze();

        for endpoint in destinations.iter() {
            let session_key = SessionKey {
                source: packet.source,
                dest: endpoint.address.to_socket_addr().await?,
            };

            sessions
                .send(session_key, packet.asn_info.clone(), contents.clone())
                .await?;
        }

        Ok(())
    }
}

#[derive(thiserror::Error, Debug, strum_macros::EnumDiscriminants)]
#[strum_discriminants(derive(strum_macros::Display))]
pub enum PipelineError {
    #[error("No upstream endpoints available")]
    NoUpstreamEndpoints,
    #[error("filter {0}")]
    Filter(#[from] crate::filters::FilterError),
    #[error("session error: {0}")]
    Session(#[from] eyre::Error),
    #[error("OS level error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Channel closed")]
    ChannelClosed,
    #[error("Under pressure")]
    ChannelFull,
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::time::{timeout, Duration};

    use crate::{
        config,
        net::endpoint::Endpoint,
        test::{
            available_addr, create_socket, load_test_filters, AddressType, TestHelper, BUFFER_POOL,
        },
    };

    #[tokio::test]
    async fn run_server() {
        let mut t = TestHelper::default();

        let endpoint1 = t.open_socket_and_recv_single_packet().await;
        let endpoint2 = t.open_socket_and_recv_single_packet().await;

        let local_addr = available_addr(&AddressType::Random).await;
        let proxy = crate::cli::Proxy {
            port: local_addr.port(),
            ..<_>::default()
        };

        let config = Arc::new(crate::Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default(
                [
                    Endpoint::new(endpoint1.socket.local_addr().unwrap().into()),
                    Endpoint::new(endpoint2.socket.local_addr().unwrap().into()),
                ]
                .into(),
            );
        });

        t.run_server(config, Some(proxy), None).await;

        tracing::trace!(%local_addr, "sending hello");
        let msg = "hello";
        endpoint1
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_millis(100), endpoint1.packet_rx)
                .await
                .expect("should get a packet")
                .unwrap()
        );
        assert_eq!(
            msg,
            timeout(Duration::from_millis(100), endpoint2.packet_rx)
                .await
                .expect("should get a packet")
                .unwrap()
        );
    }

    #[tokio::test]
    async fn run_client() {
        let mut t = TestHelper::default();

        let endpoint = t.open_socket_and_recv_single_packet().await;
        let mut local_addr = available_addr(&AddressType::Ipv6).await;
        crate::test::map_addr_to_localhost(&mut local_addr);
        let mut dest = endpoint.socket.local_ipv6_addr().unwrap();
        crate::test::map_addr_to_localhost(&mut dest);

        let proxy = crate::cli::Proxy {
            port: local_addr.port(),
            ..<_>::default()
        };

        let config = Arc::new(Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default([Endpoint::new(dest.into())].into());
        });
        t.run_server(config, Some(proxy), None).await;

        let msg = "hello";
        tracing::debug!(%local_addr, "sending packet");
        endpoint
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_millis(100), endpoint.packet_rx)
                .await
                .unwrap()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn run_with_filter() {
        let mut t = TestHelper::default();

        load_test_filters();
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = available_addr(&AddressType::Random).await;
        let mut dest = endpoint.socket.local_ipv4_addr().unwrap();
        crate::test::map_addr_to_localhost(&mut dest);
        let config = Arc::new(Config::default());
        config.filters.store(
            crate::filters::FilterChain::try_create([config::Filter {
                name: "TestFilter".to_string(),
                label: None,
                config: None,
            }])
            .map(Arc::new)
            .unwrap(),
        );
        config.clusters.modify(|clusters| {
            clusters.insert_default([Endpoint::new(dest.into())].into());
        });
        t.run_server(
            config,
            Some(crate::cli::Proxy {
                port: local_addr.port(),
                ..<_>::default()
            }),
            None,
        )
        .await;

        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();

        // search for the filter strings.
        let result = timeout(Duration::from_millis(100), endpoint.packet_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(msg), "'{}' not found in '{}'", msg, result);
        assert!(result.contains(":odr:"), ":odr: not found in '{}'", result);
    }

    #[tokio::test]
    async fn spawn_downstream_receive_workers() {
        let t = TestHelper::default();

        let (error_sender, _error_receiver) = mpsc::unbounded_channel();
        let addr = crate::test::available_addr(&AddressType::Random).await;
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let msg = "hello";
        let config = Arc::new(Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default([endpoint.socket.local_addr().unwrap().into()].into())
        });
        let (tx, rx) = async_channel::unbounded();
        let (_shutdown_tx, shutdown_rx) =
            crate::make_shutdown_channel(crate::ShutdownKind::Testing);

        // we'll test a single DownstreamReceiveWorkerConfig
        DownstreamReceiveWorkerConfig {
            worker_id: 1,
            port: addr.port(),
            upstream_receiver: rx.clone(),
            config: config.clone(),
            error_sender,
            buffer_pool: BUFFER_POOL.clone(),
            sessions: SessionPool::new(config, tx, BUFFER_POOL.clone(), shutdown_rx),
        }
        .spawn();
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let socket = create_socket().await;
        socket.send_to(msg.as_bytes(), &addr).await.unwrap();

        assert_eq!(
            msg,
            timeout(Duration::from_secs(1), endpoint.packet_rx)
                .await
                .expect("should receive a packet")
                .unwrap()
        );
    }

    #[tokio::test]
    async fn run_recv_from() {
        let t = TestHelper::default();

        let msg = "hello";
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = available_addr(&AddressType::Random).await;
        let proxy = crate::cli::Proxy {
            port: local_addr.port(),
            ..<_>::default()
        };

        let config = Arc::new(crate::Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default(
                [crate::net::endpoint::Endpoint::from(
                    endpoint.socket.local_addr().unwrap(),
                )]
                .into(),
            )
        });

        let (tx, rx) = async_channel::unbounded();
        let (_shutdown_tx, shutdown_rx) =
            crate::make_shutdown_channel(crate::ShutdownKind::Testing);

        let sessions = SessionPool::new(config.clone(), tx, BUFFER_POOL.clone(), shutdown_rx);

        proxy
            .run_recv_from(&config, proxy.port, 1, &sessions, rx, BUFFER_POOL.clone())
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let socket = create_socket().await;
        socket.send_to(msg.as_bytes(), &local_addr).await.unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(1), endpoint.packet_rx)
                .await
                .expect("should receive a packet")
                .unwrap()
        );
    }
}
