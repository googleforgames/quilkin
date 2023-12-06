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
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use tokio::{
    sync::{mpsc, RwLock},
    time::Instant,
};

use crate::{
    config::Config,
    filters::Filter,
    net::maxmind_db::IpNetEntry,
    net::DualStackLocalSocket,
    pool::{BufferPool, FrozenPoolBuffer, PoolBuffer},
    Loggable, ShutdownRx,
};

pub(crate) mod metrics;

pub type SessionMap = crate::collections::ttl::TtlMap<SessionKey, Session>;
type ChannelData = (PoolBuffer, Option<IpNetEntry>, SocketAddr);
type UpstreamChannelData = (FrozenPoolBuffer, Option<IpNetEntry>, SocketAddr);
type UpstreamSender = mpsc::Sender<UpstreamChannelData>;
type DownstreamSender = async_channel::Sender<ChannelData>;
pub type DownstreamReceiver = async_channel::Receiver<ChannelData>;

/// A data structure that is responsible for holding sessions, and pooling
/// sockets between them. This means that we only provide new unique sockets
/// to new connections to the same gameserver, and we share sockets across
/// multiple gameservers.
///
/// Traffic from different gameservers is then demuxed using their address to
/// send back to the original client.
#[derive(Debug)]
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
#[derive(Default, Debug)]
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
    async fn create_new_session_from_new_socket<'pool>(
        self: &'pool Arc<Self>,
        key: SessionKey,
        asn_info: Option<IpNetEntry>,
    ) -> Result<UpstreamSender, super::PipelineError> {
        tracing::trace!(source=%key.source, dest=%key.dest, "creating new socket for session");
        let raw_socket = crate::net::raw_socket_with_reuse(0)?;
        let port = raw_socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| eyre::eyre!("couldn't get socket address from raw socket"))
            .map_err(super::PipelineError::Session)?
            .port();
        let (tx, mut downstream_receiver) = mpsc::channel::<UpstreamChannelData>(5);

        let pool = self.clone();

        let initialised = uring_spawn!(async move {
            let mut last_received_at = None;
            let mut shutdown_rx = pool.shutdown_rx.clone();
            cfg_if::cfg_if! {
                if #[cfg(target_os = "linux")] {
                    let socket = std::rc::Rc::new(DualStackLocalSocket::from_raw(raw_socket));
                } else {
                    let socket = std::sync::Arc::new(DualStackLocalSocket::from_raw(raw_socket));
                }
            };
            let socket2 = socket.clone();

            uring_inner_spawn!(async move {
                loop {
                    match downstream_receiver.recv().await {
                        None => {
                            crate::metrics::errors_total(
                                crate::metrics::WRITE,
                                "downstream channel closed",
                                None,
                            )
                            .inc();
                        }
                        Some((data, asn_info, send_addr)) => {
                            tracing::trace!(%send_addr, length = data.len(), "sending packet upstream");
                            let (result, _) = socket2.send_to(data, send_addr).await;
                            let asn_info = asn_info.as_ref();
                            match result {
                                Ok(size) => {
                                    crate::metrics::packets_total(crate::metrics::READ, asn_info)
                                        .inc();
                                    crate::metrics::bytes_total(crate::metrics::READ, asn_info)
                                        .inc_by(size as u64);
                                }
                                Err(error) => {
                                    tracing::trace!(%error, "sending packet upstream failed");
                                    let source = error.to_string();
                                    crate::metrics::errors_total(
                                        crate::metrics::READ,
                                        &source,
                                        asn_info,
                                    )
                                    .inc();
                                    crate::metrics::packets_dropped_total(
                                        crate::metrics::READ,
                                        &source,
                                        asn_info,
                                    )
                                    .inc();
                                }
                            }
                        }
                    }
                }
            });

            loop {
                let buf = pool.buffer_pool.clone().alloc();
                tokio::select! {
                    received = socket.recv_from(buf) => {
                        let (result, buf) = received;
                        match result {
                            Err(error) => {
                                tracing::trace!(%error, "error receiving packet");
                                crate::metrics::errors_total(crate::metrics::WRITE, &error.to_string(), None).inc();
                            },
                            Ok((_size, recv_addr)) => pool.process_received_upstream_packet(buf, recv_addr, port, &mut last_received_at).await,
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Closing upstream socket loop");
                        return;
                    }
                }
            }
        });

        initialised.await.map_err(|error| eyre::eyre!(error))??;

        self.ports_to_sockets.write().await.insert(port, tx.clone());
        self.create_session_from_existing_socket(key, tx, port, asn_info)
            .await
    }

    async fn process_received_upstream_packet(
        self: &Arc<Self>,
        packet: PoolBuffer,
        mut recv_addr: SocketAddr,
        port: u16,
        last_received_at: &mut Option<i64>,
    ) {
        let received_at = chrono::Utc::now().timestamp_nanos_opt().unwrap();
        crate::net::to_canonical(&mut recv_addr);
        let (downstream_addr, asn_info): (SocketAddr, Option<IpNetEntry>) = {
            let storage = self.storage.read().await;
            let Some(downstream_addr) = storage.destination_to_sources.get(&(recv_addr, port))
            else {
                tracing::debug!(address=%recv_addr, "received traffic from a server that has no downstream");
                return;
            };
            let asn_info = storage.sources_to_asn_info.get(downstream_addr);

            (*downstream_addr, asn_info.cloned())
        };

        let asn_info = asn_info.as_ref();

        if let Some(last_received_at) = last_received_at {
            crate::metrics::packet_jitter(crate::metrics::WRITE, asn_info)
                .set(received_at - *last_received_at);
        }
        *last_received_at = Some(received_at);

        let timer = crate::metrics::processing_time(crate::metrics::WRITE).start_timer();
        let result = Self::process_recv_packet(
            self.config.clone(),
            &self.downstream_sender,
            recv_addr,
            downstream_addr,
            asn_info,
            packet,
        )
        .await;
        timer.stop_and_record();
        if let Err(error) = result {
            error.log();
            let label = format!("proxy::Session::process_recv_packet: {error}");
            crate::metrics::packets_dropped_total(crate::metrics::WRITE, &label, asn_info).inc();
            crate::metrics::errors_total(crate::metrics::WRITE, &label, asn_info).inc();
        }
    }

    /// Returns a reference to an existing session mapped to `key`, otherwise
    /// creates a new session either from a fresh socket, or if there are sockets
    /// allocated that are not reserved by an existing destination, using the
    /// existing socket.
    pub async fn get<'pool>(
        self: &'pool Arc<Self>,
        key @ SessionKey { dest, .. }: SessionKey,
        asn_info: Option<IpNetEntry>,
    ) -> Result<UpstreamSender, super::PipelineError> {
        tracing::trace!(source=%key.source, dest=%key.dest, "SessionPool::get");
        // If we already have a session for the key pairing, return that session.
        if let Some(entry) = self.session_map.get(&key) {
            tracing::trace!("returning existing session");
            return Ok(entry.upstream_sender.clone());
        }

        // If there's a socket_set available, it means there are sockets
        // allocated to the address that we want to avoid.
        let storage = self.storage.read().await;
        let Some(socket_set) = storage.destination_to_sockets.get(&dest) else {
            drop(storage);
            let no_sockets = self.ports_to_sockets.read().await.is_empty();
            return if no_sockets {
                // Initial case where we have no allocated or reserved sockets.
                self.create_new_session_from_new_socket(key, asn_info).await
            } else {
                // Where we have no allocated sockets for a destination, assign
                // the first available one.
                let (port, sender) = self
                    .ports_to_sockets
                    .read()
                    .await
                    .iter()
                    .next()
                    .map(|(port, socket)| (*port, socket.clone()))
                    .ok_or_else(|| {
                        eyre::eyre!("couldn't obtain any allocated socket, should be unreachable")
                    })
                    .map_err(super::PipelineError::Session)?;

                self.create_session_from_existing_socket(key, sender, port, asn_info)
                    .await
            };
        };

        let available_socket = self
            .ports_to_sockets
            .read()
            .await
            .iter()
            .find(|(port, _)| !socket_set.contains(port))
            .map(|(port, socket)| (*port, socket.clone()));

        if let Some((port, socket)) = available_socket {
            drop(storage);
            self.storage
                .write()
                .await
                .destination_to_sockets
                .get_mut(&dest)
                .ok_or_else(|| {
                    eyre::eyre!("couldn't obtain any socket for destination, should be unreachable")
                })
                .map_err(super::PipelineError::Session)?
                .insert(port);
            self.create_session_from_existing_socket(key, socket, port, asn_info)
                .await
        } else {
            drop(storage);
            self.create_new_session_from_new_socket(key, asn_info).await
        }
    }

    /// Using an existing socket, reserves the socket for a new session.
    async fn create_session_from_existing_socket<'session>(
        self: &'session Arc<Self>,
        key: SessionKey,
        upstream_sender: UpstreamSender,
        socket_port: u16,
        asn_info: Option<IpNetEntry>,
    ) -> Result<UpstreamSender, super::PipelineError> {
        tracing::trace!(source=%key.source, dest=%key.dest, "reusing socket for session");
        let mut storage = self.storage.write().await;
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

        if let Some(asn_info) = &asn_info {
            storage
                .sources_to_asn_info
                .insert(key.source, asn_info.clone());
        }

        drop(storage);
        let session = Session::new(
            key,
            upstream_sender.clone(),
            socket_port,
            self.clone(),
            asn_info,
        )?;
        tracing::trace!("inserting session into map");
        self.session_map.insert(key, session);
        tracing::trace!("session inserted");
        Ok(upstream_sender)
    }

    /// process_recv_packet processes a packet that is received by this session.
    async fn process_recv_packet(
        config: Arc<crate::Config>,
        downstream_sender: &DownstreamSender,
        source: SocketAddr,
        dest: SocketAddr,
        asn_info: Option<&IpNetEntry>,
        packet: PoolBuffer,
    ) -> Result<(), Error> {
        tracing::trace!(%source, %dest, length = packet.len(), "received packet from upstream");

        let mut context = crate::filters::WriteContext::new(source.into(), dest.into(), packet);

        config.filters.load().write(&mut context).await?;

        let packet = context.contents;
        tracing::trace!(%source, %dest, length = packet.len(), "sending packet downstream");
        downstream_sender
            .try_send((packet, asn_info.cloned(), dest))
            .map_err(|error| match error {
                async_channel::TrySendError::Closed(_) => Error::ChannelClosed,
                async_channel::TrySendError::Full(_) => Error::ChannelFull,
            })?;
        Ok(())
    }

    /// Returns a map of active sessions.
    pub fn sessions(&self) -> &SessionMap {
        &self.session_map
    }

    /// Sends packet data to the appropiate session based on its `key`.
    pub async fn send(
        self: &Arc<Self>,
        key: SessionKey,
        asn_info: Option<IpNetEntry>,
        packet: FrozenPoolBuffer,
    ) -> Result<(), super::PipelineError> {
        use tokio::sync::mpsc::error::TrySendError;

        self.get(key, asn_info.clone())
            .await?
            .try_send((packet, asn_info, key.dest))
            .map_err(|error| match error {
                TrySendError::Closed(_) => super::PipelineError::ChannelClosed,
                TrySendError::Full(_) => super::PipelineError::ChannelFull,
            })
    }

    /// Returns whether the pool contains any sockets allocated to a destination.
    #[cfg(test)]
    async fn has_no_allocated_sockets(&self) -> bool {
        let storage = self.storage.read().await;
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
        let mut storage = self.storage.write().await;
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
#[derive(Debug)]
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
    ) -> Result<Self, super::PipelineError> {
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
                number = asn.r#as,
                organization = asn.as_name,
                country_code = asn.as_cc,
                prefix = asn.prefix,
                prefix_entity = asn.prefix_entity,
                prefix_name = asn.prefix_name,
                "maxmind information"
            );
        }

        self::metrics::total_sessions().inc();
        s.active_session_metric().inc();
        tracing::debug!(source = %key.source, dest = %key.dest, "Session created");
        Ok(s)
    }

    fn active_session_metric(&self) -> prometheus::IntGauge {
        metrics::active_sessions(self.asn_info.as_ref())
    }

    fn async_drop(&mut self) -> impl std::future::Future<Output = ()> {
        self.active_session_metric().dec();
        metrics::duration_secs().observe(self.created_at.elapsed().as_secs() as f64);
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
    fn log(&self) {
        tracing::error!("{}", self);
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

    async fn new_pool(
        config: impl Into<Option<Config>>,
    ) -> (Arc<SessionPool>, ShutdownTx, DownstreamReceiver) {
        let (tx, rx) = crate::make_shutdown_channel(crate::ShutdownKind::Testing);
        let (sender, receiver) = async_channel::bounded(2500);
        (
            SessionPool::new(
                Arc::new(config.into().unwrap_or_default()),
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
        let (pool, _sender, _receiver) = new_pool(None).await;
        let key = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();

        let _session = pool.get(key, None).await.unwrap();

        assert!(pool.drop_session(key).await);

        assert!(pool.has_no_allocated_sockets().await);
    }

    #[tokio::test]
    async fn insert_and_release_multiple_sockets() {
        let (pool, _sender, _receiver) = new_pool(None).await;
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

        let _session1 = pool.get(key1, None).await.unwrap();
        let _session2 = pool.get(key2, None).await.unwrap();

        assert!(pool.drop_session(key1).await);
        assert!(!pool.has_no_allocated_sockets().await);
        assert!(pool.drop_session(key2).await);

        assert!(pool.has_no_allocated_sockets().await);
        drop(pool);
    }

    #[tokio::test]
    async fn same_address_uses_different_sockets() {
        let (pool, _sender, _receiver) = new_pool(None).await;
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

        let _socket1 = pool.get(key1, None).await.unwrap();
        let _socket2 = pool.get(key2, None).await.unwrap();
        assert_ne!(
            pool.session_map.get(&key1).unwrap().socket_port,
            pool.session_map.get(&key2).unwrap().socket_port
        );

        assert!(pool.drop_session(key1).await);
        assert!(pool.drop_session(key2).await);
    }

    #[tokio::test]
    async fn different_addresses_uses_same_socket() {
        let (pool, _sender, _receiver) = new_pool(None).await;
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

        let _socket1 = pool.get(key1, None).await.unwrap();
        let _socket2 = pool.get(key2, None).await.unwrap();

        assert_eq!(
            pool.session_map.get(&key1).unwrap().socket_port,
            pool.session_map.get(&key2).unwrap().socket_port
        );
    }

    #[tokio::test]
    async fn spawn_safe_same_destination() {
        let (pool, _sender, _receiver) = new_pool(None).await;
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

        let socket1 = pool.get(key1, None).await.unwrap();

        let task = tokio::spawn(async move {
            let _ = socket1;
        });

        let _socket2 = pool.get(key2, None).await.unwrap();

        task.await.unwrap();
    }

    #[tokio::test]
    async fn spawn_safe_different_destination() {
        let (pool, _sender, _receiver) = new_pool(None).await;
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

        let socket1 = pool.get(key1, None).await.unwrap();

        let task = tokio::spawn(async move {
            let _ = socket1;
        });

        let _socket2 = pool.get(key2, None).await.unwrap();

        task.await.unwrap();
    }

    #[tokio::test]
    async fn send_and_recv() {
        let mut t = TestHelper::default();
        let dest = t.run_echo_server(&AddressType::Ipv6).await;
        let mut dest = dest.to_socket_addr().await.unwrap();
        crate::test::map_addr_to_localhost(&mut dest);
        let source = available_addr(&AddressType::Ipv6).await;
        let socket = tokio::net::UdpSocket::bind(source).await.unwrap();
        let mut source = socket.local_addr().unwrap();
        crate::test::map_addr_to_localhost(&mut source);
        let (pool, _sender, receiver) = new_pool(None).await;

        let key: SessionKey = (source, dest).into();
        let msg = b"helloworld";

        pool.send(key, None, alloc_buffer(msg).freeze())
            .await
            .unwrap();

        let (data, _, _) = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(msg, &*data);
    }
}
