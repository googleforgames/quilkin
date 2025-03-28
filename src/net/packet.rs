pub mod queue;

use crate::{
    Config,
    filters::{Filter as _, ReadContext},
    metrics,
};
use std::{net::SocketAddr, sync::Arc};

pub use self::queue::{PacketQueue, PacketQueueSender, queue};
use super::{
    error::PipelineError,
    udp::sessions::{SessionKey, SessionManager},
};

/// Representation of an immutable set of bytes pulled from the network, this trait
/// provides an abstraction over however the packet was received (epoll, io-uring, xdp)
///
/// Use [`PacketDataMut`] if you need a mutable representation.
pub trait PacketData: Sized {
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
pub trait PacketDataMut: Sized + PacketData {
    type FrozenPacket: PacketData;
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

impl<P: PacketDataMut> DownstreamPacket<P> {
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

            error.inc_system_errors_total(metrics::READ, &metrics::EMPTY);
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
        let Some(clusters) = config
            .dyn_cfg
            .clusters()
            .filter(|c| c.read().has_endpoints())
        else {
            tracing::trace!("no upstream endpoints");
            return Err(PipelineError::NoUpstreamEndpoints);
        };

        let cm = clusters.clone_value();
        let Some(filters) = config.dyn_cfg.filters() else {
            return Err(PipelineError::Filter(crate::filters::FilterError::Custom(
                "no filters loaded",
            )));
        };
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
