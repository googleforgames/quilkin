use super::{
    sessions::{DownstreamReceiver, SessionKey},
    PipelineError, PipelineErrorDiscriminants, SessionPool,
};
use crate::{
    filters::{Filter as _, ReadContext},
    pool::PoolBuffer,
    Config,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;

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
            let socket = crate::net::DualStackLocalSocket::new(port)
                .unwrap()
                .make_refcnt();
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
                        source.set_ip(source.ip().to_canonical());
                        let packet = DownstreamPacket {
                            received_at: crate::unix_timestamp(),
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

/// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
/// Each received packet is placed on a queue to be processed by a worker task.
/// This function also spawns the set of worker tasks responsible for consuming packets
/// off the aforementioned queue and processing them through the filter chain and session
/// pipeline.
pub(super) fn spawn_receivers(
    config: Arc<Config>,
    socket: socket2::Socket,
    num_workers: usize,
    sessions: &Arc<SessionPool>,
    upstream_receiver: DownstreamReceiver,
    buffer_pool: Arc<crate::pool::BufferPool>,
) -> crate::Result<Vec<Arc<tokio::sync::Notify>>> {
    let (error_sender, mut error_receiver) = mpsc::unbounded_channel();

    let port = crate::net::socket_port(&socket);

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
