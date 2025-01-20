use crate::{
    components::proxy::PipelineError,
    filters::{self, Filter as _},
    metrics,
    net::EndpointAddress,
};
pub use quilkin_xdp::xdp;
use quilkin_xdp::xdp::{
    packet::{
        csum,
        net_types::{FullAddress, IpAddresses, NetworkU16, UdpPacket},
        Packet, PacketError,
    },
    HeapSlab, Umem,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
};

struct QPacket {
    inner: Packet,
    udp: UdpPacket,
}

impl filters::Packet for QPacket {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.inner
            .slice_at_offset(self.udp.data_offset, self.udp.data_length)
            .unwrap()
    }

    #[inline]
    fn len(&self) -> usize {
        self.udp.data_length
    }
}

impl filters::PacketMut for QPacket {
    type FrozenPacket = QPacket;

    fn alloc_sized(&self, _size: usize) -> Option<Self> {
        // Only used by compress filter, which we don't support
        None
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unimplemented!("only used by compress filter, which this impl doesn't wish to support")
    }

    #[inline]
    fn extend_head(&mut self, bytes: &[u8]) {
        self.inner
            .insert(self.udp.data_offset, bytes)
            .expect("failed to extend head");
        self.udp.data_length += bytes.len();
    }

    #[inline]
    fn extend_tail(&mut self, bytes: &[u8]) {
        self.inner
            .insert(self.inner.len(), bytes)
            .expect("failed to extend head");
        self.udp.data_length += bytes.len();
    }

    #[inline]
    fn remove_head(&mut self, length: usize) {
        let mut data = [0u8; 2048];

        let Ok(slice) = self
            .inner
            .slice_at_offset(self.udp.data_offset + length, self.udp.data_length - length)
        else {
            return;
        };
        let remainder = slice.len();
        data[..remainder].copy_from_slice(slice);

        let Ok(slice) = self
            .inner
            .slice_at_offset_mut(self.udp.data_offset, remainder)
        else {
            return;
        };
        slice.copy_from_slice(&data[..remainder]);

        let _ = self.inner.adjust_tail(-(length as i32));
        self.udp.data_length -= length;
    }

    #[inline]
    fn remove_tail(&mut self, length: usize) {
        let _ = self.inner.adjust_tail(-(length as i32));
        self.udp.data_length -= length;
    }

    fn set_len(&mut self, _len: usize) {
        unimplemented!("only used by compression/io_uring");
    }

    fn freeze(self) -> Self::FrozenPacket {
        unreachable!();
    }
}

pub struct State {
    /// The external port is how we determine if packets come from clients (downstream)
    /// or servers (upstream)
    pub external_port: NetworkU16,
    pub config: Arc<crate::Config>,
    pub destinations: Vec<EndpointAddress>,
    pub sessions: Arc<SessionState>,
    pub local_ipv4: std::net::Ipv4Addr,
    pub local_ipv6: std::net::Ipv6Addr,
}

impl State {
    /// Maps a remote server (upstream) endpoint back to the client endpoint
    /// that initiated the session
    #[inline]
    fn lookup_client(&self, server_addr: SocketAddr, port: NetworkU16) -> Option<SocketAddr> {
        self.sessions.lookup_client(server_addr, port)
    }

    /// Retrieves or creates a session, ie a mapping of a server endpoint + port
    /// to a client endpoint
    #[inline]
    fn session(&self, client_addr: SocketAddr, server_addr: SocketAddr) -> NetworkU16 {
        self.sessions.get_or_create(client_addr, server_addr)
    }

    #[inline]
    fn ips(&self, destination: IpAddr) -> IpAddresses {
        match destination {
            IpAddr::V4(destination) => IpAddresses::V4 {
                source: self.local_ipv4,
                destination,
            },
            IpAddr::V6(destination) => IpAddresses::V6 {
                source: self.local_ipv6,
                destination,
            },
        }
    }
}

/// Linux by default only allocates ephemeral ports between 32768..=60999
/// (see /proc/sys/net/ipv4/ip_local_port_range), so we take advantage and only
/// allocate ports above that range. Note that we check that this range hasn't
/// been modified during XDP initialization, if that changes the port mapping
/// code could cause issues
const EPHEMERAL_RANGE_END: u16 = 61000;
/// With 18 bytes per address, this lets each bucket fit in < 2k
const BUCKET_SIZE: usize = 112;

#[repr(C)]
struct Item {
    octets: [u8; 16],
    port: u16,
}

impl Item {
    #[inline]
    fn set(&mut self, addr: SocketAddr) {
        match addr {
            SocketAddr::V4(v4) => {
                // We'll never be sending to multicast addresses, so use that
                // fact to encode that this is an ipv4 address
                self.octets[0] = 0xff;
                self.octets[12..].copy_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                self.octets = v6.ip().octets();
            }
        }

        self.port = addr.port();
    }

    #[inline]
    fn get(&self) -> SocketAddr {
        if self.octets[0] == 0xff {
            (
                std::net::Ipv4Addr::new(
                    self.octets[12],
                    self.octets[13],
                    self.octets[14],
                    self.octets[15],
                ),
                self.port,
            )
                .into()
        } else {
            (std::net::Ipv6Addr::from(self.octets), self.port).into()
        }
    }
}

struct PortMap {
    buckets: Vec<[Item; BUCKET_SIZE]>,
}

impl PortMap {
    #[inline]
    fn new() -> Self {
        Self {
            // SAFETY: Item is POD
            buckets: vec![unsafe { std::mem::zeroed() }],
        }
    }

    #[inline]
    fn get(&self, port: NetworkU16) -> Option<SocketAddr> {
        let i = (port.host() - EPHEMERAL_RANGE_END) as usize;
        let bucket = i / BUCKET_SIZE;

        let bucket = self.buckets.get(bucket)?;

        // SAFETY: We know the index is valid
        unsafe {
            let item = bucket.get_unchecked(i % BUCKET_SIZE);

            // A zero port means this item was never initialized
            if item.port == 0 {
                return None;
            }

            Some(item.get())
        }
    }

    #[inline]
    fn insert(&mut self, client_addr: SocketAddr, port: u16) {
        let i = (port - EPHEMERAL_RANGE_END) as usize;
        let bucket = i / BUCKET_SIZE;
        if self.buckets.len() == bucket {
            // SAFETY: POD
            self.buckets.push(unsafe { std::mem::zeroed() });
        }

        // SAFETY: We've guaranteed we have a bucket at the index, and the
        // bucket has a fixed size of initialized bytes ready
        unsafe {
            self.buckets
                .get_unchecked_mut(bucket)
                .get_unchecked_mut(i % BUCKET_SIZE)
                .set(client_addr)
        }
    }
}

struct PortMapper {
    /// Maps a client endpoint to the port used as the source port for sending
    /// to the server endpoint `Self` is associated with
    client_to_port: Arc<parking_lot::Mutex<std::collections::HashMap<SocketAddr, NetworkU16>>>,
    port_to_client: Arc<parking_lot::RwLock<PortMap>>,
    port: AtomicU16,
}

impl PortMapper {
    #[inline]
    fn new() -> Self {
        Self {
            client_to_port: Arc::new(Default::default()),
            port_to_client: Arc::new(parking_lot::RwLock::new(PortMap::new())),
            port: AtomicU16::new(EPHEMERAL_RANGE_END),
        }
    }

    #[inline]
    fn get_or_alloc(&self, client_addr: SocketAddr) -> Option<NetworkU16> {
        match self.client_to_port.lock().entry(client_addr) {
            std::collections::hash_map::Entry::Occupied(entry) => Some(*entry.get()),
            std::collections::hash_map::Entry::Vacant(entry) => {
                let port = self.port.fetch_add(1, Ordering::Relaxed);

                if port < EPHEMERAL_RANGE_END {
                    // This means we've overflowed
                    return None;
                }

                self.port_to_client.write().insert(client_addr, port);

                let port = port.into();
                entry.insert(port);
                Some(port)
            }
        }
    }

    #[inline]
    fn get_client(&self, port: NetworkU16) -> Option<SocketAddr> {
        self.port_to_client.read().get(port)
    }
}

pub struct SessionState {
    sessions: crate::collections::ttl::TtlMap<SocketAddr, PortMapper>,
}

#[allow(clippy::derivable_impls)]
impl Default for SessionState {
    fn default() -> Self {
        Self {
            sessions: Default::default(),
        }
    }
}

impl SessionState {
    /// Attempts to lookup a client endpoint based on the server endpoint that sent
    /// the packet to the specified port
    #[inline]
    fn lookup_client(&self, server_addr: SocketAddr, port: NetworkU16) -> Option<SocketAddr> {
        self.sessions
            .get(&server_addr)
            .and_then(|pm| pm.get_client(port))
    }

    /// Retrieves the port used to forward packets from the specified client
    /// endpoint to the specified server endpoint, pairing the port to the client
    /// for forwarding packets back from the server to the client
    #[inline]
    fn get_or_create(&self, client_addr: SocketAddr, server_addr: SocketAddr) -> NetworkU16 {
        let port = match self.sessions.entry(server_addr) {
            crate::collections::ttl::Entry::Occupied(entry) => {
                entry.get().get_or_alloc(client_addr)
            }
            crate::collections::ttl::Entry::Vacant(entry) => {
                let pm = PortMapper::new();
                let port = pm.get_or_alloc(client_addr);
                entry.insert(pm);
                port
            }
        };

        if let Some(port) = port {
            return port;
        }

        // This means that this server has allocated over 4535 ports, which...could?
        // happen in some scenarios, but for now we just emit a warning, nuke the current
        // mapping. This means that if the server is still active and sends packets
        // in the future, they will either be dropped since we don't know what
        // the client endpoint is any longer, or, slightly worse, a packet gets
        // redirected to a different client.
        self.sessions.remove(server_addr);
        self.get_or_create(client_addr, server_addr)
    }
}

#[inline]
pub fn process_packets(
    rx_slab: &mut HeapSlab,
    umem: &mut Umem,
    tx_slab: &mut HeapSlab,
    state: &mut State,
) {
    let filters = state.config.filters.load();
    let cm = state.config.clusters.clone_value();

    while let Some(inner) = rx_slab.pop_front() {
        let Ok(Some(udp)) = UdpPacket::parse_packet(&inner) else {
            unreachable!("we somehow got a non-UDP packet, this should be impossible with the eBPF program we use to route packets");
        };

        let is_client = udp.destination.port == state.external_port;
        let direction = if is_client {
            metrics::READ
        } else {
            metrics::WRITE
        };

        let packet = QPacket { inner, udp };

        let res = {
            let _timer = metrics::processing_time(direction).start_timer();

            if is_client {
                process_client_packet(packet, umem, &filters, &cm, state, tx_slab)
            } else {
                process_server_packet(packet, &filters, state, tx_slab)
            }
        };

        if let Err(error) = res {
            let discriminant = error.discriminant();
            metrics::errors_total(direction, discriminant, &metrics::EMPTY).inc();
            metrics::packets_dropped_total(direction, discriminant, &metrics::EMPTY).inc();
        }
    }
}

#[inline]
fn push_packet(
    direction: metrics::Direction,
    res: Result<Packet, PacketError>,
    tx_slab: &mut HeapSlab,
) {
    match res {
        Ok(frame) => {
            if tx_slab.push_back(frame).is_some() {
                metrics::packets_dropped_total(direction, "tx slab full", &metrics::EMPTY).inc();
            }
        }
        Err(err) => {
            let discriminant = err.discriminant();
            metrics::errors_total(direction, discriminant, &metrics::EMPTY).inc();
            metrics::packets_dropped_total(direction, discriminant, &metrics::EMPTY).inc();
        }
    }
}

#[inline]
fn process_client_packet(
    packet: QPacket,
    umem: &mut Umem,
    filters: &filters::FilterChain,
    cm: &crate::net::ClusterMap,
    state: &mut State,
    tx_slab: &mut HeapSlab,
) -> Result<(), PipelineError> {
    let source_addr = SocketAddr::from((packet.udp.ips.source(), packet.udp.source.port.host()));
    let mut ctx =
        filters::ReadContext::new(cm, source_addr.into(), packet, &mut state.destinations);

    filters.read(&mut ctx).map_err(PipelineError::Filter)?;

    let filters::ReadContext {
        contents: mut packet,
        ..
    } = ctx;

    let Some(dest_addr) = state.destinations.pop() else {
        return Ok(());
    };

    let data = packet
        .inner
        .slice_at_offset(packet.udp.data_offset, packet.udp.data_length)
        .expect("data out of bounds");

    // TODO: We _could_ be more clever with this and do a running checksum calculation
    // as the packet data is modified by the filters, but for now we just do the
    // full checksum for the sake of simplicity
    let data_checksum = csum::partial(data, 0);

    // If we have more than 1 destination we need to clone the packet data to
    // a new packet for each destination, only modifying
    if !state.destinations.is_empty() {
        while let Some(daddr) = state.destinations.pop() {
            let Ok(dest_addr) = daddr.to_socket_addr() else {
                continue;
            };
            let src_port = state.session(source_addr, dest_addr);

            let mut headers = UdpPacket {
                source: FullAddress {
                    mac: packet.udp.destination.mac,
                    port: src_port,
                },
                destination: FullAddress {
                    mac: packet.udp.source.mac,
                    port: dest_addr.port().into(),
                },
                ips: state.ips(dest_addr.ip()),
                data_offset: packet.udp.data_offset,
                data_length: packet.udp.data_length,
                hop: packet.udp.hop - 1,
                checksum: NetworkU16(0),
            };

            // SAFETY: the umem outlives the frame
            let mut new_frame = unsafe {
                let Some(new_frame) = umem.alloc() else {
                    continue;
                };
                new_frame
            };

            push_packet(
                metrics::Direction::Read,
                fill_packet(&mut headers, data, data_checksum, &mut new_frame).map(|_| new_frame),
                tx_slab,
            );
        }
    }

    let Ok(dest_addr) = dest_addr.to_socket_addr() else {
        return Ok(());
    };
    let src_port = state.session(source_addr, dest_addr);

    let mut headers = UdpPacket {
        source: FullAddress {
            mac: packet.udp.destination.mac,
            port: src_port,
        },
        destination: FullAddress {
            mac: packet.udp.source.mac,
            port: dest_addr.port().into(),
        },
        ips: state.ips(dest_addr.ip()),
        data_offset: packet.udp.data_offset,
        data_length: packet.udp.data_length,
        hop: packet.udp.hop - 1,
        checksum: NetworkU16(0),
    };

    headers.calc_checksum(data.len(), data_checksum);

    push_packet(
        metrics::Direction::Read,
        modify_packet_headers(&packet.udp, &headers, &mut packet.inner).map(|_| packet.inner),
        tx_slab,
    );

    Ok(())
}

#[inline]
fn process_server_packet(
    packet: QPacket,
    filters: &crate::filters::FilterChain,
    state: &mut State,
    tx_slab: &mut HeapSlab,
) -> Result<(), PipelineError> {
    let server_addr = SocketAddr::new(packet.udp.ips.source(), packet.udp.source.port.host());

    let Some(client_addr) = state.lookup_client(server_addr, packet.udp.destination.port) else {
        tracing::debug!(address = %server_addr, "received traffic from a server that has no downstream");
        return Ok(());
    };

    let mut ctx = filters::WriteContext::new(server_addr.into(), client_addr.into(), packet);
    filters.write(&mut ctx).map_err(PipelineError::Filter)?;

    let filters::WriteContext {
        contents: mut packet,
        ..
    } = ctx;

    let headers = UdpPacket {
        source: FullAddress {
            mac: packet.udp.destination.mac,
            port: state.external_port,
        },
        destination: FullAddress {
            mac: packet.udp.source.mac,
            port: client_addr.port().into(),
        },
        ips: state.ips(client_addr.ip()),
        data_offset: packet.udp.data_offset,
        data_length: packet.udp.data_length,
        hop: packet.udp.hop - 1,
        checksum: NetworkU16(0),
    };

    push_packet(
        metrics::Direction::Write,
        modify_packet_headers(&packet.udp, &headers, &mut packet.inner).map(|_| {
            let _ = csum::recalc_udp(&mut packet.inner);
            packet.inner
        }),
        tx_slab,
    );
    Ok(())
}

/// Modifies the headers of an existing well formed packet to a new source and destination,
/// resizing the header portion as needed if changing between ipv4 and ipv6
#[inline]
fn modify_packet_headers(
    original: &UdpPacket,
    new: &UdpPacket,
    packet: &mut Packet,
) -> Result<(), PacketError> {
    match (original.is_ipv4(), new.is_ipv4()) {
        (true, false) => packet.adjust_head(-20)?,
        (false, true) => packet.adjust_head(20)?,
        (_, _) => {}
    }

    new.set_packet_headers(packet)?;
    Ok(())
}

#[inline]
fn fill_packet(
    headers: &mut UdpPacket,
    data: &[u8],
    data_checksum: u32,
    frame: &mut Packet,
) -> Result<(), PacketError> {
    let hdr_len = headers.header_length();
    frame.adjust_tail(hdr_len as i32)?;
    headers.calc_checksum(data.len(), data_checksum);
    headers.set_packet_headers(frame)?;
    frame.insert(hdr_len, data)?;
    Ok(())
}
