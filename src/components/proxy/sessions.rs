/*
 * Copyright 2020 Google LLC
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

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::{sync::mpsc, time::Instant};

use crate::{
    components::proxy::{PipelineError, SendPacket},
    config::Config,
    filters::Filter,
    metrics,
    net::maxmind_db::{IpNetEntry, MetricsIpNetEntry},
    pool::{BufferPool, FrozenPoolBuffer, PoolBuffer},
    time::UtcTimestamp,
    Loggable, ShutdownRx,
};

use parking_lot::RwLock;

pub(crate) mod inner_metrics;

pub type SessionMap = crate::collections::ttl::TtlMap<SessionKey, Session>;

#[cfg(target_os = "linux")]
mod io_uring;
#[cfg(not(target_os = "linux"))]
mod reference;

type UpstreamSender = mpsc::Sender<super::SendPacket>;

type DownstreamSender = async_channel::Sender<super::SendPacket>;
pub type DownstreamReceiver = async_channel::Receiver<super::SendPacket>;

#[derive(PartialEq, Eq, Hash)]
pub enum SessionError {
    SocketAddressUnavailable,
    MissingAllocatedSocket,
    MissingDestinationSocket,
}

impl std::error::Error for SessionError {}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketAddressUnavailable => {
                f.write_str("couldn't get socket address from raw socket")
            }
            Self::MissingAllocatedSocket => {
                f.write_str("couldn't obtain any allocated socket, should be unreachable")
            }
            Self::MissingDestinationSocket => {
                f.write_str("couldn't obtain any socket for destination, should be unreachable")
            }
        }
    }
}

impl fmt::Debug for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// A data structure that is responsible for holding sessions, and pooling
/// sockets between them. This means that we only provide new unique sockets
/// to new connections to the same gameserver, and we share sockets across
/// multiple gameservers.
///
/// Traffic from different gameservers is then demuxed using their address to
/// send back to the original client.
pub struct SessionPool {
    ports_to_sockets: RwLock<HashMap<u16, UpstreamSender>>,
    storage: Arc<RwLock<SocketStorage>>,
    session_map: SessionMap,
    downstream_sender: DownstreamSender,
    buffer_pool: Arc<BufferPool>,
    shutdown_rx: ShutdownRx,
    config: Arc<Config>,
}

/// The wrapper struct responsible for holding all of the socket related mappings.
#[derive(Default)]
struct SocketStorage {
    destination_to_sockets: HashMap<SocketAddr, HashSet<u16>>,
    destination_to_sources: HashMap<(SocketAddr, u16), SocketAddr>,
    sources_to_asn_info: HashMap<SocketAddr, IpNetEntry>,
    sockets_to_destination: HashMap<u16, HashSet<SocketAddr>>,
}

impl SessionPool {
    /// Constructs a new session pool, it's created with an `Arc` as that's
    /// required for the pool to provide a reference to the children to be able
    /// to release their sockets back to the parent.
    pub fn new(
        config: Arc<Config>,
        downstream_sender: DownstreamSender,
        buffer_pool: Arc<BufferPool>,
        shutdown_rx: ShutdownRx,
    ) -> Arc<Self> {
        const SESSION_TIMEOUT_SECONDS: Duration = Duration::from_secs(60);
        const SESSION_EXPIRY_POLL_INTERVAL: Duration = Duration::from_secs(60);

        Arc::new(Self {
            config,
            downstream_sender,
            shutdown_rx,
            ports_to_sockets: <_>::default(),
            storage: <_>::default(),
            session_map: SessionMap::new(SESSION_TIMEOUT_SECONDS, SESSION_EXPIRY_POLL_INTERVAL),
            buffer_pool,
        })
    }

    /// Allocates a new upstream socket from a new socket from the system.
    fn create_new_session_from_new_socket<'pool>(
        self: &'pool Arc<Self>,
        key: SessionKey,
    ) -> Result<(Option<MetricsIpNetEntry>, UpstreamSender), super::PipelineError> {
        tracing::trace!(source=%key.source, dest=%key.dest, "creating new socket for session");
        let raw_socket = crate::net::raw_socket_with_reuse(0)?;
        let port = raw_socket
            .local_addr()?
            .as_socket()
            .ok_or(SessionError::SocketAddressUnavailable)?
            .port();
        let (downstream_sender, downstream_receiver) = mpsc::channel::<super::SendPacket>(15);

        let initialised = self
            .clone()
            .spawn_session(raw_socket, port, downstream_receiver)?;
        initialised
            .recv()
            .map_err(|_err| PipelineError::ChannelClosed)?;

        self.ports_to_sockets
            .write()
            .insert(port, downstream_sender.clone());
        self.create_session_from_existing_socket(key, downstream_sender, port)
    }

    pub(crate) fn process_received_upstream_packet(
        self: &Arc<Self>,
        packet: PoolBuffer,
        mut recv_addr: SocketAddr,
        port: u16,
        last_received_at: &mut Option<UtcTimestamp>,
    ) {
        let received_at = UtcTimestamp::now();
        recv_addr.set_ip(recv_addr.ip().to_canonical());
        let (downstream_addr, asn_info): (SocketAddr, Option<MetricsIpNetEntry>) = {
            let storage = self.storage.read();
            let Some(downstream_addr) = storage.destination_to_sources.get(&(recv_addr, port))
            else {
                tracing::debug!(address=%recv_addr, "received traffic from a server that has no downstream");
                return;
            };
            let asn_info = storage.sources_to_asn_info.get(downstream_addr);

            (*downstream_addr, asn_info.map(MetricsIpNetEntry::from))
        };

        let asn_metric_info = asn_info.as_ref().into();

        if let Some(last_received_at) = last_received_at {
            metrics::packet_jitter(metrics::WRITE, &asn_metric_info)
                .set((received_at - *last_received_at).nanos());
        }
        *last_received_at = Some(received_at);

        let result = {
            let _timer = metrics::processing_time(metrics::WRITE).start_timer();
            Self::process_recv_packet(
                self.config.clone(),
                &self.downstream_sender,
                recv_addr,
                downstream_addr,
                asn_info,
                packet,
            )
        };

        if let Err((asn_info, error)) = result {
            error.log();
            let label = format!("proxy::Session::process_recv_packet: {error}");
            let asn_metric_info = asn_info.as_ref().into();

            metrics::packets_dropped_total(metrics::WRITE, &label, &asn_metric_info).inc();
            metrics::errors_total(metrics::WRITE, &label, &asn_metric_info).inc();
        }
    }

    /// Returns a reference to an existing session mapped to `key`, otherwise
    /// creates a new session either from a fresh socket, or if there are sockets
    /// allocated that are not reserved by an existing destination, using the
    /// existing socket.
    pub fn get<'pool>(
        self: &'pool Arc<Self>,
        key @ SessionKey { dest, .. }: SessionKey,
    ) -> Result<(Option<MetricsIpNetEntry>, UpstreamSender), super::PipelineError> {
        tracing::trace!(source=%key.source, dest=%key.dest, "SessionPool::get");
        // If we already have a session for the key pairing, return that session.
        if let Some(entry) = self.session_map.get(&key) {
            tracing::trace!("returning existing session");
            return Ok((
                entry.asn_info.as_ref().map(MetricsIpNetEntry::from),
                entry.upstream_sender.clone(),
            ));
        }

        // If there's a socket_set available, it means there are sockets
        // allocated to the address that we want to avoid.
        let storage = self.storage.read();
        let Some(socket_set) = storage.destination_to_sockets.get(&dest) else {
            drop(storage);
            let no_sockets = self.ports_to_sockets.read().is_empty();
            return if no_sockets {
                // Initial case where we have no allocated or reserved sockets.
                self.create_new_session_from_new_socket(key)
            } else {
                // Where we have no allocated sockets for a destination, assign
                // the first available one.
                let (port, sender) = self
                    .ports_to_sockets
                    .read()
                    .iter()
                    .next()
                    .map(|(port, socket)| (*port, socket.clone()))
                    .ok_or(SessionError::MissingAllocatedSocket)?;

                self.create_session_from_existing_socket(key, sender, port)
            };
        };

        let available_socket = self
            .ports_to_sockets
            .read()
            .iter()
            .find(|(port, _)| !socket_set.contains(port))
            .map(|(port, socket)| (*port, socket.clone()));

        if let Some((port, socket)) = available_socket {
            drop(storage);
            self.storage
                .write()
                .destination_to_sockets
                .get_mut(&dest)
                .ok_or(SessionError::MissingDestinationSocket)?
                .insert(port);
            self.create_session_from_existing_socket(key, socket, port)
        } else {
            drop(storage);
            self.create_new_session_from_new_socket(key)
        }
    }

    /// Using an existing socket, reserves the socket for a new session.
    fn create_session_from_existing_socket<'session>(
        self: &'session Arc<Self>,
        key: SessionKey,
        upstream_sender: UpstreamSender,
        socket_port: u16,
    ) -> Result<(Option<MetricsIpNetEntry>, UpstreamSender), super::PipelineError> {
        tracing::trace!(source=%key.source, dest=%key.dest, "reusing socket for session");
        let asn_info = {
            let mut storage = self.storage.write();
            storage
                .destination_to_sockets
                .entry(key.dest)
                .or_default()
                .insert(socket_port);
            storage
                .sockets_to_destination
                .entry(socket_port)
                .or_default()
                .insert(key.dest);
            storage
                .destination_to_sources
                .insert((key.dest, socket_port), key.source);

            let asn_info = crate::net::maxmind_db::MaxmindDb::lookup(key.source.ip());

            if let Some(asn_info) = &asn_info {
                storage
                    .sources_to_asn_info
                    .insert(key.source, asn_info.clone());
            }

            asn_info
        };

        let asn_metrics_info = asn_info.as_ref().map(MetricsIpNetEntry::from);

        let session = Session::new(
            key,
            upstream_sender.clone(),
            socket_port,
            self.clone(),
            asn_info,
        );
        tracing::trace!("inserting session into map");
        self.session_map.insert(key, session);
        tracing::trace!("session inserted");
        Ok((asn_metrics_info, upstream_sender))
    }

    /// process_recv_packet processes a packet that is received by this session.
    fn process_recv_packet(
        config: Arc<crate::Config>,
        downstream_sender: &DownstreamSender,
        source: SocketAddr,
        dest: SocketAddr,
        asn_info: Option<MetricsIpNetEntry>,
        packet: PoolBuffer,
    ) -> Result<(), (Option<MetricsIpNetEntry>, Error)> {
        tracing::trace!(%source, %dest, length = packet.len(), "received packet from upstream");

        let mut context = crate::filters::WriteContext::new(source.into(), dest.into(), packet);

        if let Err(err) = config.filters.load().write(&mut context) {
            return Err((asn_info, err.into()));
        }

        let packet = context.contents.freeze();
        tracing::trace!(%source, %dest, length = packet.len(), "sending packet downstream");
        downstream_sender
            .try_send(SendPacket {
                data: packet,
                destination: dest,
                asn_info,
            })
            .map_err(|error| match error {
                async_channel::TrySendError::Closed(packet) => {
                    (packet.asn_info, Error::ChannelClosed)
                }
                async_channel::TrySendError::Full(packet) => (packet.asn_info, Error::ChannelFull),
            })?;
        Ok(())
    }

    /// Returns a map of active sessions.
    pub fn sessions(&self) -> &SessionMap {
        &self.session_map
    }

    /// Sends packet data to the appropiate session based on its `key`.
    pub fn send(
        self: &Arc<Self>,
        key: SessionKey,
        packet: FrozenPoolBuffer,
    ) -> Result<(), super::PipelineError> {
        use tokio::sync::mpsc::error::TrySendError;

        let (asn_info, sender) = self.get(key)?;

        sender
            .try_send(crate::components::proxy::SendPacket {
                data: packet,
                asn_info,
                destination: key.dest,
            })
            .map_err(|error| match error {
                TrySendError::Closed(_) => super::PipelineError::ChannelClosed,
                TrySendError::Full(_) => super::PipelineError::ChannelFull,
            })
    }

    /// Returns whether the pool contains any sockets allocated to a destination.
    #[cfg(test)]
    fn has_no_allocated_sockets(&self) -> bool {
        let storage = self.storage.read();
        let is_empty = storage.destination_to_sockets.is_empty();
        // These should always be the same.
        debug_assert!(!(is_empty ^ storage.sockets_to_destination.is_empty()));
        is_empty
    }

    /// Forces removal of session to make testing quicker.
    #[cfg(test)]
    async fn drop_session(&self, key: SessionKey) -> bool {
        let is_removed = self.session_map.remove(key);
        // Sleep because there's no async drop.
        tokio::time::sleep(Duration::from_millis(100)).await;
        is_removed
    }

    /// Handles the logic of releasing a socket back into the pool.
    async fn release_socket(
        self: Arc<Self>,
        SessionKey {
            ref source,
            ref dest,
        }: SessionKey,
        port: u16,
    ) {
        tracing::trace!("releasing socket");
        let mut storage = self.storage.write();
        let Some(socket_set) = storage.destination_to_sockets.get_mut(dest) else {
            return;
        };

        socket_set.remove(&port);

        if socket_set.is_empty() {
            storage.destination_to_sockets.remove(dest);
        }

        let Some(dest_set) = storage.sockets_to_destination.get_mut(&port) else {
            return;
        };

        dest_set.remove(dest);

        if dest_set.is_empty() {
            storage.sockets_to_destination.remove(&port);
        }

        // Not asserted because the source might not have GeoIP info.
        storage.sources_to_asn_info.remove(source);
        storage.destination_to_sources.remove(&(*dest, port));
        tracing::trace!("socket released");
    }
}

impl Drop for SessionPool {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.session_map));
    }
}

/// Session encapsulates a UDP stream session
pub struct Session {
    /// created_at is time at which the session was created
    created_at: Instant,
    /// The source and destination pair.
    key: SessionKey,
    /// The socket port of the session.
    socket_port: u16,
    /// The socket of the session.
    upstream_sender: UpstreamSender,
    /// The GeoIP information of the source.
    asn_info: Option<IpNetEntry>,
    /// The socket pool of the session.
    pool: Arc<SessionPool>,
}

impl Session {
    pub fn new(
        key: SessionKey,
        upstream_sender: UpstreamSender,
        socket_port: u16,
        pool: Arc<SessionPool>,
        asn_info: Option<IpNetEntry>,
    ) -> Self {
        let s = Self {
            key,
            upstream_sender,
            pool,
            socket_port,
            asn_info,
            created_at: Instant::now(),
        };

        if let Some(asn) = &s.asn_info {
            tracing::debug!(
                number = asn.id,
                organization = asn.as_name,
                country_code = asn.as_cc,
                prefix = asn.prefix,
                prefix_entity = asn.prefix_entity,
                prefix_name = asn.prefix_name,
                "maxmind information"
            );
        }

        inner_metrics::total_sessions().inc();
        s.active_session_metric().inc();
        tracing::debug!(source = %key.source, dest = %key.dest, "Session created");
        s
    }

    fn active_session_metric(&self) -> prometheus::IntGauge {
        inner_metrics::active_sessions(self.asn_info.as_ref())
    }

    fn async_drop(&mut self) -> impl std::future::Future<Output = ()> {
        self.active_session_metric().dec();
        inner_metrics::duration_secs().observe(self.created_at.elapsed().as_secs() as f64);
        tracing::debug!(source = %self.key.source, dest_address = %self.key.dest, "Session closed");
        SessionPool::release_socket(self.pool.clone(), self.key, self.socket_port)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        tokio::spawn(self.async_drop());
    }
}

// A (source, destination) address pair that uniquely identifies a session.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Debug, PartialOrd, Ord)]
pub struct SessionKey {
    pub source: SocketAddr,
    pub dest: SocketAddr,
}

impl From<(SocketAddr, SocketAddr)> for SessionKey {
    fn from((source, dest): (SocketAddr, SocketAddr)) -> Self {
        Self { source, dest }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("downstream channel closed")]
    ChannelClosed,
    #[error("downstream channel full")]
    ChannelFull,
    #[error("filter {0}")]
    Filter(#[from] crate::filters::FilterError),
}

impl Loggable for Error {
    #[inline]
    fn log(&self) {
        tracing::error!("{self}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test::{alloc_buffer, available_addr, AddressType, TestHelper},
        ShutdownTx,
    };
    use std::sync::Arc;

    async fn new_pool() -> (Arc<SessionPool>, ShutdownTx, DownstreamReceiver) {
        let (tx, rx) = crate::make_shutdown_channel(crate::ShutdownKind::Testing);
        let (sender, receiver) = async_channel::unbounded();
        (
            SessionPool::new(
                Arc::new(Config::default_agent()),
                sender,
                Arc::new(BufferPool::default()),
                rx,
            ),
            tx,
            receiver,
        )
    }

    #[tokio::test]
    async fn insert_and_release_single_socket() {
        let (pool, _sender, _receiver) = new_pool().await;
        let key = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();

        let _session = pool.get(key).unwrap();

        assert!(pool.drop_session(key).await);

        assert!(pool.has_no_allocated_sockets());
    }

    #[tokio::test]
    async fn insert_and_release_multiple_sockets() {
        let (pool, _sender, _receiver) = new_pool().await;
        let key1 = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();
        let key2 = (
            (std::net::Ipv4Addr::LOCALHOST, 8081u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();

        let _session1 = pool.get(key1).unwrap();
        let _session2 = pool.get(key2).unwrap();

        assert!(pool.drop_session(key1).await);
        assert!(!pool.has_no_allocated_sockets());
        assert!(pool.drop_session(key2).await);

        assert!(pool.has_no_allocated_sockets());
        drop(pool);
    }

    #[tokio::test]
    async fn same_address_uses_different_sockets() {
        let (pool, _sender, _receiver) = new_pool().await;
        let key1 = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();
        let key2 = (
            (std::net::Ipv4Addr::LOCALHOST, 8081u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();

        let _socket1 = pool.get(key1).unwrap();
        let _socket2 = pool.get(key2).unwrap();
        assert_ne!(
            pool.session_map.get(&key1).unwrap().socket_port,
            pool.session_map.get(&key2).unwrap().socket_port
        );

        assert!(pool.drop_session(key1).await);
        assert!(pool.drop_session(key2).await);
    }

    #[tokio::test]
    async fn different_addresses_uses_same_socket() {
        let (pool, _sender, _receiver) = new_pool().await;
        let key1 = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();
        let key2 = (
            (std::net::Ipv4Addr::LOCALHOST, 8081u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8081u16).into(),
        )
            .into();

        let _socket1 = pool.get(key1).unwrap();
        let _socket2 = pool.get(key2).unwrap();

        assert_eq!(
            pool.session_map.get(&key1).unwrap().socket_port,
            pool.session_map.get(&key2).unwrap().socket_port
        );
    }

    #[tokio::test]
    async fn spawn_safe_same_destination() {
        let (pool, _sender, _receiver) = new_pool().await;
        let key1 = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();
        let key2 = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();

        let socket1 = pool.get(key1).unwrap();

        let task = tokio::spawn(async move {
            let _ = socket1;
        });

        let _socket2 = pool.get(key2).unwrap();

        task.await.unwrap();
    }

    #[tokio::test]
    async fn spawn_safe_different_destination() {
        let (pool, _sender, _receiver) = new_pool().await;
        let key1 = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();
        let key2 = (
            (std::net::Ipv4Addr::LOCALHOST, 8081u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8081u16).into(),
        )
            .into();

        let socket1 = pool.get(key1).unwrap();

        let task = tokio::spawn(async move {
            let _ = socket1;
        });

        let _socket2 = pool.get(key2).unwrap();

        task.await.unwrap();
    }

    #[tokio::test]
    #[cfg_attr(target_os = "macos", ignore)]
    async fn send_and_recv() {
        let mut t = TestHelper::default();
        let dest = t.run_echo_server(AddressType::Ipv6).await;
        let mut dest = dest.to_socket_addr().unwrap();
        crate::test::map_addr_to_localhost(&mut dest);
        let source = available_addr(AddressType::Ipv6).await;
        let socket = tokio::net::UdpSocket::bind(source).await.unwrap();
        let mut source = socket.local_addr().unwrap();
        crate::test::map_addr_to_localhost(&mut source);
        let (pool, _sender, receiver) = new_pool().await;

        let key: SessionKey = (source, dest).into();
        let msg = b"helloworld";

        pool.send(key, alloc_buffer(msg).freeze()).unwrap();

        let packet = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(msg, &*packet.data);
    }
}
