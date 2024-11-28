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

use super::{sessions::SessionKey, PipelineError, SessionPool};
use crate::{
    filters::{Filter as _, ReadContext},
    metrics,
    pool::PoolBuffer,
    Config,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
mod io_uring;
#[cfg(not(target_os = "linux"))]
mod reference;

/// Packet received from local port
pub(crate) struct DownstreamPacket {
    pub(crate) contents: PoolBuffer,
    //received_at: UtcTimestamp,
    pub(crate) source: SocketAddr,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub struct DownstreamReceiveWorkerConfig {
    /// ID of the worker.
    pub worker_id: usize,
    pub port: u16,
    pub config: Arc<Config>,
    pub sessions: Arc<SessionPool>,
    pub error_sender: super::error::ErrorSender,
    pub buffer_pool: Arc<crate::pool::BufferPool>,
}

impl DownstreamReceiveWorkerConfig {
    #[inline]
    pub(crate) fn process_task(
        packet: DownstreamPacket,
        worker_id: usize,
        config: &Arc<Config>,
        sessions: &Arc<SessionPool>,
        error_acc: &mut super::error::ErrorAccumulator,
        destinations: &mut Vec<crate::net::EndpointAddress>,
    ) {
        tracing::trace!(
            id = worker_id,
            size = packet.contents.len(),
            source = %packet.source,
            "received packet from downstream"
        );

        let timer = metrics::processing_time(metrics::READ).start_timer();
        match Self::process_downstream_received_packet(packet, config, sessions, destinations) {
            Ok(()) => {
                error_acc.maybe_send();
            }
            Err(error) => {
                let discriminant = error.discriminant();
                metrics::errors_total(metrics::READ, discriminant, &metrics::EMPTY).inc();
                metrics::packets_dropped_total(metrics::READ, discriminant, &metrics::EMPTY).inc();

                error_acc.push_error(error);
            }
        }

        timer.stop_and_record();
    }

    /// Processes a packet by running it through the filter chain.
    #[inline]
    fn process_downstream_received_packet(
        packet: DownstreamPacket,
        config: &Arc<Config>,
        sessions: &Arc<SessionPool>,
        destinations: &mut Vec<crate::net::EndpointAddress>,
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
            destinations,
        );
        filters.read(&mut context).map_err(PipelineError::Filter)?;

        let ReadContext { contents, .. } = context;

        // Similar to bytes::BytesMut::freeze, we turn the mutable pool buffer
        // into an immutable one with its own internal arc so it can be cloned
        // cheaply and returned to the pool once all references are dropped
        let contents = contents.freeze();

        for epa in destinations.drain(0..) {
            let session_key = SessionKey {
                source: packet.source,
                dest: epa.to_socket_addr()?,
            };

            sessions.send(session_key, contents.clone())?;
        }

        Ok(())
    }
}

/// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
/// Each received packet is placed on a queue to be processed by a worker task.
/// This function also spawns the set of worker tasks responsible for consuming packets
/// off the aforementioned queue and processing them through the filter chain and session
/// pipeline.
pub(crate) async fn spawn_receivers(
    config: Arc<Config>,
    socket: socket2::Socket,
    worker_sends: Vec<(super::PendingSends, super::PacketSendReceiver)>,
    sessions: &Arc<SessionPool>,
    buffer_pool: Arc<crate::pool::BufferPool>,
) -> crate::Result<()> {
    let (error_sender, mut error_receiver) = mpsc::channel(128);

    let port = crate::net::socket_port(&socket);

    for (worker_id, ws) in worker_sends.into_iter().enumerate() {
        let worker = DownstreamReceiveWorkerConfig {
            worker_id,
            port,
            config: config.clone(),
            sessions: sessions.clone(),
            error_sender: error_sender.clone(),
            buffer_pool: buffer_pool.clone(),
        };

        worker.spawn(ws).await?;
    }

    drop(error_sender);

    tokio::spawn(async move {
        let mut log_task = tokio::time::interval(std::time::Duration::from_secs(5));

        #[allow(clippy::mutable_key_type)]
        let mut pipeline_errors = super::error::ErrorMap::default();

        #[allow(clippy::mutable_key_type)]
        fn report(errors: &mut super::error::ErrorMap) {
            for (error, instances) in errors.drain() {
                tracing::warn!(%error, %instances, "pipeline report");
            }
        }

        loop {
            tokio::select! {
                _ = log_task.tick() => {
                    report(&mut pipeline_errors);
                }
                received = error_receiver.recv() => {
                    let Some(errors) = received else {
                        report(&mut pipeline_errors);
                        tracing::info!("pipeline reporting task closed");
                        return;
                    };

                    for (k, v) in errors {
                        *pipeline_errors.entry(k).or_default() += v;
                    }
                }
            }
        }
    });

    Ok(())
}
