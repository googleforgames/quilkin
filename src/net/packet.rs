pub mod queue;

use crate::{
    Config,
    filters::{Filter as _, ReadContext},
    metrics,
};
use std::{net::SocketAddr, sync::Arc};

use super::{
    error::PipelineError,
    sessions::{SessionKey, SessionManager},
};

pub use queue::{PacketQueue, PacketQueueSender, SendPacket, queue};

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

        #[cfg(not(debug_assertions))]
        match self.source.ip() {
            std::net::IpAddr::V4(ipv4) => {
                if ipv4.is_loopback() || ipv4.is_multicast() || ipv4.is_broadcast() {
                    return Err(PipelineError::DisallowedSourceIP(self.source.ip()));
                }
            }
            std::net::IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() || ipv6.is_multicast() {
                    return Err(PipelineError::DisallowedSourceIP(self.source.ip()));
                }
            }
        }

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

#[cfg(test)]
mod tests {
    #![cfg(not(debug_assertions))]

    use quilkin_xds::locality::Locality;

    use crate::collections::BufferPool;
    use crate::net::{Endpoint, io::Backend, sessions::SessionPool};
    use crate::test::alloc_buffer;

    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::net::{SocketAddrV4, SocketAddrV6};

    // Ensure we disallow certain source IP addresses to protect against UDP amplification attacks
    #[tokio::test]
    async fn disallowed_ips() {
        let nl1 = Locality::with_region("nl-1");
        let endpoint = Endpoint::new((Ipv4Addr::LOCALHOST, 7777).into());

        let config = Arc::new(Config::default_agent().cluster(
            None,
            Some(nl1.clone()),
            [endpoint.clone()].into(),
        ));
        let buffer_pool = Arc::new(BufferPool::new(1, 10));
        let session_manager = SessionPool::new(
            config.clone(),
            vec![],
            buffer_pool.clone(),
            Backend::Polling,
        );

        let packet_data: [u8; 4] = [1, 2, 3, 4];
        for ip in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            // multicast = 224.0.0.0/4
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
            IpAddr::V4(Ipv4Addr::new(239, 255, 255, 255)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            // multicast = any address starting with 0xff
            IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
        ] {
            let packet = DownstreamPacket {
                contents: alloc_buffer(packet_data),
                source: match ip {
                    IpAddr::V4(ipv4) => SocketAddr::V4(SocketAddrV4::new(ipv4, 0)),
                    IpAddr::V6(ipv6) => SocketAddr::V6(SocketAddrV6::new(ipv6, 0, 0, 0)),
                },
            };

            let mut endpoints = vec![endpoint.address.clone()];
            let res = packet.process_inner(&config, &session_manager, &mut endpoints);

            assert_eq!(res, Err(PipelineError::DisallowedSourceIP(ip)));
        }
    }
}
