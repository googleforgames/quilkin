use super::{
    sessions::{DownstreamReceiver, SessionKey},
    PipelineError, PipelineErrorDiscriminants, SessionPool,
};
use crate::{
    filters::{Filter as _, ReadContext},
    metrics,
    pool::PoolBuffer,
    time::UtcTimestamp,
    Config,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;

/// Packet received from local port
#[derive(Debug)]
struct DownstreamPacket {
    contents: PoolBuffer,
    received_at: UtcTimestamp,
    source: SocketAddr,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub struct DownstreamReceiveWorkerConfig {
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
    pub async fn spawn(self) -> eyre::Result<Arc<tokio::sync::Notify>> {
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

        let thread_span =
            uring_span!(tracing::debug_span!("receiver", id = worker_id).or_current());

        let worker = uring_spawn!(thread_span, async move {
            let mut last_received_at = None;
            let socket = crate::net::DualStackLocalSocket::new(port)
                .unwrap()
                .make_refcnt();

            tracing::trace!(port, "bound worker");
            let send_socket = socket.clone();

            let inner_task = async move {
                is_ready.notify_one();

                loop {
                    tokio::select! {
                        result = upstream_receiver.recv() => {
                            match result {
                                Err(error) => {
                                    tracing::trace!(%error, "error receiving packet");
                                    metrics::errors_total(
                                        metrics::WRITE,
                                        &error.to_string(),
                                        &metrics::EMPTY,
                                        )
                                        .inc();
                                }
                                Ok((data, asn_info, send_addr)) => {
                                    let (result, _) = send_socket.send_to(data, send_addr).await;
                                    let asn_info = asn_info.as_ref().into();
                                    match result {
                                        Ok(size) => {
                                            metrics::packets_total(metrics::WRITE, &asn_info)
                                                .inc();
                                            metrics::bytes_total(metrics::WRITE, &asn_info)
                                                .inc_by(size as u64);
                                        }
                                        Err(error) => {
                                            let source = error.to_string();
                                            metrics::errors_total(
                                                metrics::WRITE,
                                                &source,
                                                &asn_info,
                                                )
                                                .inc();
                                            metrics::packets_dropped_total(
                                                metrics::WRITE,
                                                &source,
                                                &asn_info,
                                                )
                                                .inc();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            };

            cfg_if::cfg_if! {
                if #[cfg(debug_assertions)] {
                    uring_inner_spawn!(inner_task.instrument(tracing::debug_span!("upstream").or_current()));
                } else {
                    uring_inner_spawn!(inner_task);
                }
            }

            loop {
                // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
                // packet, which is the maximum value of 16 a bit integer.
                let buffer = buffer_pool.clone().alloc();

                let (result, contents) = socket.recv_from(buffer).await;

                match result {
                    Ok((_size, mut source)) => {
                        source.set_ip(source.ip().to_canonical());
                        let packet = DownstreamPacket {
                            received_at: UtcTimestamp::now(),
                            contents,
                            source,
                        };

                        if let Some(last_received_at) = last_received_at {
                            metrics::packet_jitter(metrics::READ, &metrics::EMPTY)
                                .set((packet.received_at - last_received_at).nanos());
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

        use eyre::WrapErr as _;
        worker.await.context("failed to spawn receiver task")??;
        Ok(notify)
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

        let timer = metrics::processing_time(metrics::READ).start_timer();
        match Self::process_downstream_received_packet(packet, config, sessions).await {
            Ok(()) => {}
            Err(error) => {
                let discriminant = PipelineErrorDiscriminants::from(&error).to_string();
                metrics::errors_total(metrics::READ, &discriminant, &metrics::EMPTY).inc();
                metrics::packets_dropped_total(metrics::READ, &discriminant, &metrics::EMPTY).inc();
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

        for epa in destinations {
            let session_key = SessionKey {
                source: packet.source,
                dest: epa.to_socket_addr().await?,
            };

            sessions.send(session_key, contents.clone()).await?;
        }

        Ok(())
    }
}

/// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
/// Each received packet is placed on a queue to be processed by a worker task.
/// This function also spawns the set of worker tasks responsible for consuming packets
/// off the aforementioned queue and processing them through the filter chain and session
/// pipeline.
pub async fn spawn_receivers(
    config: Arc<Config>,
    socket: socket2::Socket,
    num_workers: usize,
    sessions: &Arc<SessionPool>,
    upstream_receiver: DownstreamReceiver,
    buffer_pool: Arc<crate::pool::BufferPool>,
) -> crate::Result<Vec<Arc<tokio::sync::Notify>>> {
    let (error_sender, mut error_receiver) = mpsc::unbounded_channel();

    let port = crate::net::socket_port(&socket);

    let mut worker_notifications = Vec::with_capacity(num_workers);
    for worker_id in 0..num_workers {
        let worker = DownstreamReceiveWorkerConfig {
            worker_id,
            upstream_receiver: upstream_receiver.clone(),
            port,
            config: config.clone(),
            sessions: sessions.clone(),
            error_sender: error_sender.clone(),
            buffer_pool: buffer_pool.clone(),
        };

        worker_notifications.push(worker.spawn().await?);
    }

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
