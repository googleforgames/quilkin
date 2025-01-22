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

use super::{
    sessions::{SessionKey, SessionManager},
    PipelineError, SessionPool,
};
use crate::{
    filters::{Filter as _, ReadContext},
    metrics, Config,
};
use std::{net::SocketAddr, sync::Arc};

#[cfg(target_os = "linux")]
mod io_uring;
#[cfg(not(target_os = "linux"))]
mod reference;

/// Representation of an immutable set of bytes pulled from the network, this trait
/// provides an abstraction over however the packet was received (epoll, io-uring, xdp)
///
/// Use [PacketMut] if you need a mutable representation.
pub trait Packet: Sized {
    /// Returns the underlying slice of bytes representing the packet.
    fn as_slice(&self) -> &[u8];

    /// Returns the size of the packet.
    fn len(&self) -> usize;

    /// Returns whether the given packet is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Representation of an mutable set of bytes pulled from the network, this trait
/// provides an abstraction over however the packet was received (epoll, io-uring, xdp)
pub trait PacketMut: Sized + Packet {
    type FrozenPacket: Packet;
    fn alloc_sized(&self, size: usize) -> Option<Self>;
    fn as_mut_slice(&mut self) -> &mut [u8];
    fn set_len(&mut self, len: usize);
    fn remove_head(&mut self, length: usize);
    fn remove_tail(&mut self, length: usize);
    fn extend_head(&mut self, bytes: &[u8]);
    fn extend_tail(&mut self, bytes: &[u8]);
    /// Returns an immutable version of the packet, this allows certain types
    /// return a type that can be more cheaply cloned and shared.
    fn freeze(self) -> Self::FrozenPacket;
}

/// Packet received from local port
pub(crate) struct DownstreamPacket<P> {
    pub(crate) contents: P,
    pub(crate) source: SocketAddr,
}

impl<P: PacketMut> DownstreamPacket<P> {
    #[inline]
    pub(crate) fn process<S: SessionManager<Packet = P::FrozenPacket>>(
        self,
        worker_id: usize,
        config: &Arc<Config>,
        sessions: &S,
        destinations: &mut Vec<crate::net::EndpointAddress>,
    ) {
        tracing::trace!(
            id = worker_id,
            size = self.contents.len(),
            source = %self.source,
            "received packet from downstream"
        );

        let timer = metrics::processing_time(metrics::READ).start_timer();
        if let Err(error) = self.process_inner(config, sessions, destinations) {
            let discriminant = error.discriminant();

            // We only want to mark potential I/O errors as errors, as they
            // can indicate something wrong with the system, error variants
            // from packets being bad aren't errors from quilkin's perspective.
            if matches!(
                error,
                PipelineError::Io(_) | PipelineError::Filter(crate::filters::FilterError::Io(_))
            ) {
                metrics::errors_total(metrics::READ, discriminant, &metrics::EMPTY).inc();
            }
            metrics::packets_dropped_total(metrics::READ, discriminant, &metrics::EMPTY).inc();
        }

        timer.stop_and_record();
    }

    /// Processes a packet by running it through the filter chain.
    #[inline]
    fn process_inner<S: SessionManager<Packet = P::FrozenPacket>>(
        self,
        config: &Arc<Config>,
        sessions: &S,
        destinations: &mut Vec<crate::net::EndpointAddress>,
    ) -> Result<(), PipelineError> {
        if !config.clusters.read().has_endpoints() {
            tracing::trace!("no upstream endpoints");
            return Err(PipelineError::NoUpstreamEndpoints);
        }

        let cm = config.clusters.clone_value();
        let filters = config.filters.load();
        let mut context = ReadContext::new(&cm, self.source.into(), self.contents, destinations);
        filters.read(&mut context).map_err(PipelineError::Filter)?;

        let ReadContext { contents, .. } = context;

        // Similar to bytes::BytesMut::freeze, we turn the mutable pool buffer
        // into an immutable one with its own internal arc so it can be cloned
        // cheaply and returned to the pool once all references are dropped
        let contents = contents.freeze();

        for epa in destinations.drain(0..) {
            let session_key = SessionKey {
                source: self.source,
                dest: epa.to_socket_addr()?,
            };

            sessions.send(session_key, &contents)?;
        }

        Ok(())
    }
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub struct DownstreamReceiveWorkerConfig {
    /// ID of the worker.
    pub worker_id: usize,
    pub port: u16,
    pub config: Arc<Config>,
    pub sessions: Arc<SessionPool>,
    pub buffer_pool: Arc<crate::collections::BufferPool>,
}

/// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
/// Each received packet is placed on a queue to be processed by a worker task.
/// This function also spawns the set of worker tasks responsible for consuming packets
/// off the aforementioned queue and processing them through the filter chain and session
/// pipeline.
pub fn spawn_receivers(
    config: Arc<Config>,
    socket: socket2::Socket,
    worker_sends: Vec<crate::net::PacketQueue>,
    sessions: &Arc<SessionPool>,
    buffer_pool: Arc<crate::collections::BufferPool>,
) -> crate::Result<()> {
    let port = crate::net::socket_port(&socket);

    for (worker_id, ws) in worker_sends.into_iter().enumerate() {
        let worker = DownstreamReceiveWorkerConfig {
            worker_id,
            port,
            config: config.clone(),
            sessions: sessions.clone(),
            buffer_pool: buffer_pool.clone(),
        };

        worker.spawn(ws)?;
    }

    Ok(())
}
