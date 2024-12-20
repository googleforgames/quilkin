use crate::{filters, metrics};
use quilkin_xdp::xdp::frame::net_types::NetworkU16;

pub(super) struct State {
    /// The external port is how we determine if packets come from clients (downstream)
    /// or servers (upstream)
    external_port: NetworkU16,
}

#[inline]
fn process_packets(
    recvd: &mut xpd::Slab<Frame>,
    umem: &mut xdp::Umem,
    tx: &mut xdp::TxRing,
    external_port: NetworkU16,
    config: &crate::Config,
) -> usize {
    let mut sent = 0;
    let filters = config.filters.load();
    while let Some(packet) = recvd.pop_front() {
        let Ok(Some(udp_packet)) = UdpPacket::parse_frame(&packet) else {
            unreachable!("we somehow got a non-UDP packet, this should be impossible with the eBPF program we use to route packets");
        };

        sent += if udp_packet.destination.port == external_port {
            process_client_packet(packet, udp_packet, umem, tx, &filters)
        } else {
            process_server_packet(packet, udp_packet, umem, tx, &filters)
        };
    }

    sent
}

#[inline]
fn process_client_packet(
    packet: Frame,
    udp: UdpPacket,
    umem: &mut xdp::Umem,
    tx: &mut xdp::TxRing,
    filters: &crate::filters::FilterChain,
) -> usize {
    let timer = metrics::processing_time(metrics::READ).start_timer();

    let mut context = filters::ReadContext::new(
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
}

#[inline]
fn process_server_packet(
    packet: Frame,
    udp: UdpPacket,
    umem: &mut xdp::Umem,
    tx: &mut xdp::TxRing,
    filters: &crate::filters::FilterChain,
) -> usize {
}
