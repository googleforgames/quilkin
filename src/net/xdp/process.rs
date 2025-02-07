use crate::{
    components::proxy::{sessions::inner_metrics as session_metrics, PipelineError},
    filters::{self, Filter as _},
    metrics::{self, AsnInfo},
    net::{
        maxmind_db::{self, IpNetEntry},
        EndpointAddress,
    },
};
pub use quilkin_xdp::xdp;
use quilkin_xdp::xdp::{
    packet::{
        csum,
        net_types::{IpAddresses, NetworkU16, UdpPacket},
        Packet, PacketError,
    },
    HeapSlab, Umem,
};
use std::{
    collections::hash_map::Entry,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Instant,
};

/// Wrapper around the actual packet buffer and the UDP metadata it parsed to
/// so that we can satisify the filter traits
struct PacketWrapper {
    inner: Packet,
    udp: UdpPacket,
}

impl filters::Packet for PacketWrapper {
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

impl filters::PacketMut for PacketWrapper {
    type FrozenPacket = PacketWrapper;

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

    // Only used in the io-uring implementation
    fn freeze(self) -> Self::FrozenPacket {
        unreachable!();
    }
}

pub struct State {
    /// The external port is how we determine if packets come from clients (downstream)
    /// or servers (upstream)
    pub external_port: NetworkU16,
    pub qcmp_port: NetworkU16,
    pub config: Arc<crate::Config>,
    pub destinations: Vec<EndpointAddress>,
    pub addr_to_asn: std::collections::HashMap<IpAddr, Option<(IpNetEntry, maxmind_db::Asn)>>,
    pub sessions: Arc<SessionState>,
    pub local_ipv4: std::net::Ipv4Addr,
    pub local_ipv6: std::net::Ipv6Addr,
}

impl State {
    /// Maps a remote server (upstream) endpoint back to the client endpoint
    /// that initiated the session
    #[inline]
    fn lookup_client(
        &self,
        server_addr: SocketAddr,
        port: NetworkU16,
    ) -> Option<(SocketAddr, AsnInfo<'_>)> {
        let addr = self.sessions.lookup_client(server_addr, port)?;
        let entry = self
            .addr_to_asn
            .get(&addr.ip())
            .and_then(|ipe| {
                ipe.as_ref().map(|(ipe, asn)| AsnInfo {
                    prefix: &ipe.prefix,
                    asn: asn.as_str(),
                })
            })
            .unwrap_or(metrics::EMPTY);

        Some((addr, entry))
    }

    /// Retrieves or creates a session, ie a mapping of a server endpoint + port
    /// to a client endpoint
    #[inline]
    fn session(
        &mut self,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> (NetworkU16, AsnInfo<'_>, IpAddresses) {
        let ips = self.ips(server_addr.ip());
        let asn = self.addr_to_asn.entry(client_addr.ip()).or_insert_with(|| {
            let ipe = maxmind_db::MaxmindDb::lookup(client_addr.ip());
            ipe.map(|ipe| {
                let asn = maxmind_db::Asn::new(ipe.id);
                (ipe, asn)
            })
        });

        let port =
            self.sessions
                .get_or_create(client_addr, server_addr, asn.as_ref().map(|(ipe, _)| ipe));

        (
            port,
            asn.as_ref()
                .map(|(ipe, asn)| AsnInfo {
                    prefix: &ipe.prefix,
                    asn: asn.as_str(),
                })
                .unwrap_or(metrics::EMPTY),
            ips,
        )
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

struct ClientInfo {
    asn_info: Option<IpNetEntry>,
    created_at: Instant,
    /// The port used to identify this unique session to the IP owning this map
    port: NetworkU16,
}

struct PortMapper {
    /// Maps a client endpoint to the port used as the source port for sending
    /// to the server endpoint `Self` is associated with
    client_to_port: Arc<parking_lot::Mutex<std::collections::HashMap<SocketAddr, ClientInfo>>>,
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
    fn get_or_alloc(
        &self,
        client_addr: SocketAddr,
        asn: Option<&IpNetEntry>,
    ) -> Option<NetworkU16> {
        match self.client_to_port.lock().entry(client_addr) {
            Entry::Occupied(entry) => Some(entry.get().port),
            Entry::Vacant(entry) => {
                let port = self.port.fetch_add(1, Ordering::Relaxed);

                if port < EPHEMERAL_RANGE_END {
                    // This means we've overflowed
                    return None;
                }

                session_metrics::total_sessions().inc();
                session_metrics::active_sessions(asn).inc();

                self.port_to_client.write().insert(client_addr, port);

                let port = port.into();
                entry.insert(ClientInfo {
                    asn_info: asn.cloned(),
                    created_at: Instant::now(),
                    port,
                });
                Some(port)
            }
        }
    }

    #[inline]
    fn get_client(&self, port: NetworkU16) -> Option<SocketAddr> {
        self.port_to_client.read().get(port)
    }
}

impl Drop for PortMapper {
    fn drop(&mut self) {
        let lock = self.client_to_port.lock();

        let now = Instant::now();

        for client_info in lock.values() {
            session_metrics::active_sessions(client_info.asn_info.as_ref()).dec();
            session_metrics::duration_secs()
                .observe(now.duration_since(client_info.created_at).as_secs_f64());
        }
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
    fn get_or_create(
        &self,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        asn: Option<&IpNetEntry>,
    ) -> NetworkU16 {
        let port = match self.sessions.entry(server_addr) {
            crate::collections::ttl::Entry::Occupied(entry) => {
                entry.get().get_or_alloc(client_addr, asn)
            }
            crate::collections::ttl::Entry::Vacant(entry) => {
                let pm = PortMapper::new();
                let port = pm.get_or_alloc(client_addr, asn);
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
        self.get_or_create(client_addr, server_addr, asn)
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

        if udp.dst_port == state.qcmp_port {
            process_qcmp_packet(inner, udp, umem, tx_slab);
            continue;
        }

        let is_client = udp.dst_port == state.external_port;
        let direction = if is_client {
            metrics::READ
        } else {
            metrics::WRITE
        };

        let packet = PacketWrapper { inner, udp };

        let res = {
            let _timer = metrics::processing_time(direction).start_timer();

            if is_client {
                process_client_packet(packet, umem, &filters, &cm, state, tx_slab)
            } else {
                process_server_packet(packet, umem, &filters, state, tx_slab)
            }
        };

        match res {
            Ok(None) => {}
            Ok(Some(packet)) => {
                umem.free_packet(packet);
            }
            Err((error, packet)) => {
                let discriminant = error.discriminant();
                error.inc_system_errors_total(direction, &metrics::EMPTY);
                metrics::packets_dropped_total(direction, discriminant, &metrics::EMPTY).inc();

                umem.free_packet(packet);
            }
        }
    }
}

#[inline]
fn push_packet(
    direction: metrics::Direction,
    packet: Packet,
    asn: AsnInfo<'_>,
    data_length: usize,
    res: Result<(), PacketError>,
    tx_slab: &mut HeapSlab,
    umem: &mut Umem,
) {
    match res {
        Ok(()) => {
            if let Some(packet) = tx_slab.push_back(packet) {
                metrics::packets_dropped_total(direction, "tx slab full", &metrics::EMPTY).inc();
                umem.free_packet(packet);
            } else {
                metrics::packets_total(direction, &asn).inc();
                metrics::bytes_total(direction, &asn).inc_by(data_length as u64);
            }
        }
        Err(err) => {
            let discriminant = err.discriminant();
            metrics::errors_total(direction, discriminant, &metrics::EMPTY).inc();
            metrics::packets_dropped_total(direction, discriminant, &metrics::EMPTY).inc();
            umem.free_packet(packet);
        }
    }
}

#[inline]
fn process_client_packet(
    packet: PacketWrapper,
    umem: &mut Umem,
    filters: &filters::FilterChain,
    cm: &crate::net::ClusterMap,
    state: &mut State,
    tx_slab: &mut HeapSlab,
) -> Result<Option<Packet>, (PipelineError, Packet)> {
    let source_addr = SocketAddr::from((packet.udp.ips.source(), packet.udp.src_port.host()));
    let mut ctx =
        filters::ReadContext::new(cm, source_addr.into(), packet, &mut state.destinations);

    let mut packet = match filters.read(&mut ctx) {
        Ok(()) => ctx.contents,
        Err(err) => {
            return Err((PipelineError::Filter(err), ctx.contents.inner));
        }
    };

    let Some(dest_addr) = state.destinations.pop() else {
        return Ok(Some(packet.inner));
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
            let (src_port, asn, ips) = state.session(source_addr, dest_addr);

            let mut headers = UdpPacket {
                src_mac: packet.udp.dst_mac,
                src_port,
                dst_mac: packet.udp.src_mac,
                dst_port: dest_addr.port().into(),
                ips,
                data_offset: packet.udp.data_offset,
                data_length: packet.udp.data_length,
                hop: packet.udp.hop - 1,
                checksum: NetworkU16(0),
            };

            // SAFETY: the umem outlives the frame
            let mut new_packet = unsafe {
                let Some(new_packet) = umem.alloc() else {
                    continue;
                };
                new_packet
            };

            let res = fill_packet(&mut headers, data, data_checksum, &mut new_packet);
            push_packet(
                metrics::Direction::Read,
                new_packet,
                asn,
                packet.udp.data_length,
                res,
                tx_slab,
                umem,
            );
        }
    }

    let Ok(dest_addr) = dest_addr.to_socket_addr() else {
        return Ok(Some(packet.inner));
    };
    let (src_port, asn, ips) = state.session(source_addr, dest_addr);

    let mut headers = UdpPacket {
        src_mac: packet.udp.dst_mac,
        src_port,
        dst_mac: packet.udp.src_mac,
        dst_port: dest_addr.port().into(),
        ips,
        data_offset: packet.udp.data_offset,
        data_length: packet.udp.data_length,
        hop: packet.udp.hop - 1,
        checksum: NetworkU16(0),
    };

    headers.calc_checksum(data.len(), data_checksum);

    let res = modify_packet_headers(&packet.udp, &headers, &mut packet.inner);
    push_packet(
        metrics::Direction::Read,
        packet.inner,
        asn,
        packet.udp.data_length,
        res,
        tx_slab,
        umem,
    );

    Ok(None)
}

#[inline]
fn process_server_packet(
    packet: PacketWrapper,
    umem: &mut Umem,
    filters: &crate::filters::FilterChain,
    state: &mut State,
    tx_slab: &mut HeapSlab,
) -> Result<Option<Packet>, (PipelineError, Packet)> {
    let server_addr = SocketAddr::new(packet.udp.ips.source(), packet.udp.src_port.host());

    let Some((client_addr, asn)) = state.lookup_client(server_addr, packet.udp.dst_port) else {
        tracing::debug!(address = %server_addr, "received traffic from a server that has no downstream");
        return Ok(Some(packet.inner));
    };

    let mut ctx = filters::WriteContext::new(server_addr.into(), client_addr.into(), packet);

    let mut packet = match filters.write(&mut ctx) {
        Ok(()) => ctx.contents,
        Err(err) => {
            return Err((PipelineError::Filter(err), ctx.contents.inner));
        }
    };

    let headers = UdpPacket {
        src_mac: packet.udp.dst_mac,
        src_port: state.external_port,
        dst_mac: packet.udp.src_mac,
        dst_port: client_addr.port().into(),
        ips: state.ips(client_addr.ip()),
        data_offset: packet.udp.data_offset,
        data_length: packet.udp.data_length,
        hop: packet.udp.hop - 1,
        checksum: NetworkU16(0),
    };

    let res = modify_packet_headers(&packet.udp, &headers, &mut packet.inner);
    if res.is_ok() {
        let _ = packet.inner.calc_udp_checksum();
    }

    push_packet(
        metrics::Direction::Write,
        packet.inner,
        asn,
        packet.udp.data_length,
        res,
        tx_slab,
        umem,
    );
    Ok(None)
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

fn process_qcmp_packet(
    mut packet: Packet,
    udp: UdpPacket,
    umem: &mut Umem,
    tx_slab: &mut HeapSlab,
) {
    use crate::{codec::qcmp, time::UtcTimestamp};

    fn inner(packet: &mut Packet, udp: UdpPacket) -> bool {
        let received_at = UtcTimestamp::now();
        let data = match packet.slice_at_offset(udp.data_offset, udp.data_length) {
            Ok(d) => d,
            Err(error) => {
                tracing::debug!(%error, "corrupt UDP packet");
                return false;
            }
        };
        let command = match qcmp::Protocol::parse(data) {
            Ok(Some(command)) => command,
            Ok(None) => {
                tracing::debug!("rejected non-qcmp packet");
                return false;
            }
            Err(error) => {
                tracing::debug!(%error, "rejected malformed packet");
                return false;
            }
        };

        let qcmp::Protocol::Ping {
            client_timestamp,
            nonce,
        } = command
        else {
            tracing::warn!("rejected unsupported QCMP packet");
            return false;
        };

        let mut ob = qcmp::QcmpPacket::default();
        let buf = qcmp::Protocol::ping_reply(nonce, client_timestamp, received_at).encode(&mut ob);

        if let Err(error) = packet.adjust_tail(-(udp.data_length as i32)) {
            tracing::debug!(%error, "unable to trim QCMP ping data");
            return false;
        }

        if let Err(error) = packet.insert(udp.data_offset, buf) {
            tracing::debug!(%error, "unable to write QCMP pong data");
            return false;
        }

        let new = UdpPacket {
            src_mac: udp.dst_mac,
            dst_mac: udp.src_mac,
            ips: match udp.ips {
                IpAddresses::V4 {
                    source,
                    destination,
                } => IpAddresses::V4 {
                    source: destination,
                    destination: source,
                },
                IpAddresses::V6 {
                    source,
                    destination,
                } => IpAddresses::V6 {
                    source: destination,
                    destination: source,
                },
            },
            src_port: udp.dst_port,
            dst_port: udp.src_port,
            data_offset: udp.data_offset,
            data_length: buf.len(),
            hop: udp.hop - 1,
            checksum: 0.into(),
        };

        if let Err(error) = modify_packet_headers(&udp, &new, packet) {
            tracing::debug!(%error, "unable to modify QCMP packet headers");
            return false;
        }

        if let Err(error) = packet.calc_udp_checksum() {
            tracing::debug!(%error, "failed to calculate QCMP packet checksum");
            return false;
        }

        true
    }

    let packet = if inner(&mut packet, udp) {
        tracing::debug!("sending QCMP pong");

        if let Some(packet) = tx_slab.push_back(packet) {
            tracing::debug!("tx slab full, unable to send QCMP pong");
            packet
        } else {
            return;
        }
    } else {
        packet
    };

    umem.free_packet(packet);
}
