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
use sessions::{SessionKey, SessionPool};

#[cfg(doc)]
use crate::filters::FilterFactory;

use crate::{
    filters::{Filter, ReadContext},
    net::{xds::ResourceType, DualStackLocalSocket},
    Config, Result, ShutdownRx,
};

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
    #[clap(long, env = "QUILKIN_IDLE_REQUEST_INTERVAL_SECS", default_value_t = super::admin::IDLE_REQUEST_INTERVAL_SECS)]
    pub idle_request_interval_secs: u64,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            management_server: <_>::default(),
            mmdb: <_>::default(),
            port: PORT,
            qcmp_port: QCMP_PORT,
            to: <_>::default(),
            idle_request_interval_secs: super::admin::IDLE_REQUEST_INTERVAL_SECS,
        }
    }
}

impl Proxy {
    /// Start and run a proxy.
    pub async fn run(
        &self,
        config: std::sync::Arc<crate::Config>,
        mode: Admin,
        mut shutdown_rx: ShutdownRx,
    ) -> crate::Result<()> {
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
        let shared_socket = Arc::new(DualStackLocalSocket::new(self.port)?);
        let sessions = SessionPool::new(config.clone(), shared_socket.clone(), shutdown_rx.clone());

        let _xds_stream = if !self.management_server.is_empty() {
            {
                let mut lock = runtime_config.xds_is_healthy.write();
                let check: Arc<AtomicBool> = <_>::default();
                *lock = Some(check.clone());
            }

            let client = crate::net::xds::AdsClient::connect(
                String::clone(&id),
                mode.clone(),
                self.management_server.clone(),
            )
            .await?;
            let mut stream =
                client.xds_client_stream(config.clone(), self.idle_request_interval_secs);

            tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
            stream.discovery_request(ResourceType::Cluster, &[]).await?;
            tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
            stream
                .discovery_request(ResourceType::Listener, &[])
                .await?;
            Some((client, stream))
        } else {
            None
        };

        self.run_recv_from(&config, &sessions, shared_socket)?;
        crate::codec::qcmp::spawn(self.qcmp_port).await?;
        tracing::info!("Quilkin is ready");

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
        sessions: &Arc<SessionPool>,
        shared_socket: Arc<DualStackLocalSocket>,
    ) -> Result<()> {
        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = num_cpus::get();
        let (error_sender, mut error_receiver) = mpsc::unbounded_channel();

        // Contains config for each worker task.
        let mut workers = Vec::with_capacity(num_workers);
        workers.push(DownstreamReceiveWorkerConfig {
            worker_id: 0,
            socket: shared_socket,
            config: config.clone(),
            sessions: sessions.clone(),
            error_sender: error_sender.clone(),
        });

        for worker_id in 1..num_workers {
            workers.push(DownstreamReceiveWorkerConfig {
                worker_id,
                socket: Arc::new(DualStackLocalSocket::new(self.port)?),
                config: config.clone(),
                sessions: sessions.clone(),
                error_sender: error_sender.clone(),
            })
        }

        // Start the worker tasks that pick up received packets from their queue
        // and processes them.
        for worker in workers {
            worker.spawn();
        }

        tokio::spawn(async move {
            let mut log_task = tokio::time::interval(std::time::Duration::from_secs(5));

            let mut pipeline_errors = std::collections::HashMap::<String, u64>::new();
            loop {
                tokio::select! {
                    _ = log_task.tick() => {
                        for (error, instances) in &pipeline_errors {
                            tracing::info!(%error, %instances, "pipeline report");
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

        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuntimeConfig {
    pub idle_request_interval_secs: u64,
    // RwLock as this check is conditional on the proxy using xDS.
    pub xds_is_healthy: Arc<parking_lot::RwLock<Option<Arc<AtomicBool>>>>,
}

impl RuntimeConfig {
    pub fn is_ready(&self, config: &Config) -> bool {
        self.xds_is_healthy
            .read()
            .as_ref()
            .map_or(true, |health| health.load(Ordering::SeqCst))
            && config.clusters.read().has_endpoints()
    }
}

/// Packet received from local port
#[derive(Debug)]
struct DownstreamPacket {
    asn_info: Option<crate::net::maxmind_db::IpNetEntry>,
    contents: Vec<u8>,
    received_at: i64,
    source: SocketAddr,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub(crate) struct DownstreamReceiveWorkerConfig {
    /// ID of the worker.
    pub worker_id: usize,
    /// Socket with reused port from which the worker receives packets.
    pub socket: Arc<DualStackLocalSocket>,
    pub config: Arc<Config>,
    pub sessions: Arc<SessionPool>,
    pub error_sender: mpsc::UnboundedSender<PipelineError>,
}

impl DownstreamReceiveWorkerConfig {
    pub fn spawn(self) {
        let Self {
            worker_id,
            socket,
            config,
            sessions,
            error_sender,
        } = self;

        tokio::spawn(async move {
            // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
            // packet, which is the maximum value of 16 a bit integer.
            let mut buf = vec![0; 1 << 16];
            let mut last_received_at = None;
            loop {
                tracing::trace!(
                    id = worker_id,
                    port = ?socket.local_ipv6_addr().map(|addr| addr.port()),
                    "Awaiting packet"
                );

                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((size, mut source)) => {
                                crate::net::to_canonical(&mut source);
                                let packet = DownstreamPacket {
                                    received_at: chrono::Utc::now().timestamp_nanos_opt().unwrap(),
                                    asn_info: crate::net::maxmind_db::MaxmindDb::lookup(source.ip()),
                                    contents: buf[..size].to_vec(),
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

                                Self::process_task(packet, source, worker_id, &config, &sessions, &error_sender).await;
                            }
                            Err(error) => {
                                tracing::error!(%error, "error receiving packet");
                                return;
                            }
                        }
                    }
                }
            }
        });
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
            contents=&*crate::codec::base64::encode(&packet.contents),
            "received packet from downstream"
        );

        let timer = crate::metrics::processing_time(crate::metrics::READ).start_timer();

        let asn_info = packet.asn_info.clone();
        let asn_info = asn_info.as_ref();
        match Self::process_downstream_received_packet(packet, config, sessions).await {
            Ok(size) => {
                crate::metrics::packets_total(crate::metrics::READ, asn_info).inc();
                crate::metrics::bytes_total(crate::metrics::READ, asn_info).inc_by(size as u64);
            }
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
    ) -> Result<usize, PipelineError> {
        if !config.clusters.read().has_endpoints() {
            return Err(PipelineError::NoUpstreamEndpoints);
        }

        let filters = config.filters.load();
        let mut context = ReadContext::new(
            config.clusters.clone_value(),
            packet.source.into(),
            packet.contents,
        );
        filters.read(&mut context).await?;
        let mut bytes_written = 0;

        for endpoint in context.destinations.iter() {
            let session_key = SessionKey {
                source: packet.source,
                dest: endpoint.address.to_socket_addr().await?,
            };

            bytes_written += sessions
                .send(session_key, packet.asn_info.clone(), &context.contents)
                .await?;
        }

        Ok(bytes_written)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::time::{timeout, Duration};

    use crate::{
        config,
        net::endpoint::Endpoint,
        test::{available_addr, create_socket, load_test_filters, AddressType, TestHelper},
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
                    Endpoint::new(endpoint1.socket.local_ipv4_addr().unwrap().into()),
                    Endpoint::new(endpoint2.socket.local_ipv6_addr().unwrap().into()),
                ]
                .into(),
            );
        });

        t.run_server(config, proxy, None);

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
        t.run_server(config, proxy, None);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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
            crate::filters::FilterChain::try_from(vec![config::Filter {
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
            crate::cli::Proxy {
                port: local_addr.port(),
                ..<_>::default()
            },
            None,
        );

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
        let socket = Arc::new(create_socket().await);
        let addr = socket.local_ipv6_addr().unwrap();
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let msg = "hello";
        let config = Arc::new(Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default([endpoint.socket.local_ipv6_addr().unwrap().into()].into())
        });

        // we'll test a single DownstreamReceiveWorkerConfig
        DownstreamReceiveWorkerConfig {
            worker_id: 1,
            socket: socket.clone(),
            config: config.clone(),
            error_sender,
            sessions: SessionPool::new(
                config,
                Arc::new(
                    DualStackLocalSocket::new(
                        crate::test::available_addr(&AddressType::Random)
                            .await
                            .port(),
                    )
                    .unwrap(),
                ),
                crate::make_shutdown_channel(crate::ShutdownKind::Testing).1,
            ),
        }
        .spawn();

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
                    endpoint.socket.local_ipv4_addr().unwrap(),
                )]
                .into(),
            )
        });

        let shared_socket = Arc::new(
            DualStackLocalSocket::new(
                crate::test::available_addr(&AddressType::Random)
                    .await
                    .port(),
            )
            .unwrap(),
        );
        let sessions = SessionPool::new(
            config.clone(),
            shared_socket.clone(),
            crate::make_shutdown_channel(crate::ShutdownKind::Testing).1,
        );

        proxy
            .run_recv_from(&config, &sessions, shared_socket)
            .unwrap();

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
