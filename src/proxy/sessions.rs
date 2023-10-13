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
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use tokio::{sync::watch, time::Instant};

use crate::{
    config::Config,
    filters::Filter,
    maxmind_db::IpNetEntry,
    utils::{net::DualStackLocalSocket, Loggable},
};

use parking_lot::RwLock;

use dashmap::DashMap;

pub(crate) mod metrics;

pub type SessionMap = crate::ttl_map::TtlMap<SessionKey, Session>;

type SessionRef<'pool> =
    dashmap::mapref::one::Ref<'pool, SessionKey, crate::ttl_map::Value<Session>>;

/// A data structure that is responsible for holding sessions, and pooling
/// sockets between them. This means that we only provide new unique sockets
/// to new connections to the same gameserver, and we share sockets across
/// multiple gameservers.
///
/// Traffic from different gameservers is then demuxed using their address to
/// send back to the original client.
#[derive(Debug)]
pub struct SessionPool {
    ports_to_sockets: DashMap<u16, Arc<DualStackLocalSocket>>,
    storage: RwLock<SocketStorage>,
    session_map: SessionMap,
    downstream_socket: Arc<DualStackLocalSocket>,
    shutdown_rx: watch::Receiver<()>,
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
        downstream_socket: DualStackLocalSocket,
        shutdown_rx: watch::Receiver<()>,
    ) -> Arc<Self> {
        const SESSION_TIMEOUT_SECONDS: Duration = Duration::from_secs(60);
        const SESSION_EXPIRY_POLL_INTERVAL: Duration = Duration::from_secs(60);

        Arc::new(Self {
            config,
            downstream_socket: Arc::new(downstream_socket),
            shutdown_rx,
            ports_to_sockets: <_>::default(),
            storage: <_>::default(),
            session_map: SessionMap::new(SESSION_TIMEOUT_SECONDS, SESSION_EXPIRY_POLL_INTERVAL),
        })
    }

    /// Allocates a new upstream socket from a new socket from the system.
    async fn create_new_session_from_new_socket<'pool>(
        self: &'pool Arc<Self>,
        key: SessionKey,
        asn_info: Option<IpNetEntry>,
    ) -> Result<SessionRef<'pool>, super::PipelineError> {
        let socket = DualStackLocalSocket::new(0).map(Arc::new)?;
        let port = socket.local_ipv4_addr().unwrap().port();
        self.ports_to_sockets.insert(port, socket.clone());

        let upstream_socket = socket.clone();
        let pool = self.clone();
        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            let mut last_received_at = None;
            let mut shutdown_rx = pool.shutdown_rx.clone();

            loop {
                tokio::select! {
                    received = upstream_socket.recv_from(&mut buf) => {
                        match received {
                            Err(error) => {
                                tracing::trace!(%error, "error receiving packet");
                                crate::metrics::errors_total(crate::metrics::WRITE, &error.to_string(), None).inc();
                            },
                            Ok((size, mut recv_addr)) => {
                                let received_at = chrono::Utc::now().timestamp_nanos_opt().unwrap();
                                tracing::trace!(%recv_addr, %size, "received packet");
                                let (downstream_addr, asn_info): (SocketAddr, Option<IpNetEntry>) = {
                                    let storage = pool.storage.read();
                                    to_canonical(&mut recv_addr);
                                    let Some(downstream_addr) = storage.destination_to_sources.get(&(recv_addr, port)) else {
                                        tracing::warn!(address=%recv_addr, "received traffic from a server that has no downstream");
                                        continue;
                                    };
                                    let asn_info = storage.sources_to_asn_info.get(downstream_addr);

                                    (*downstream_addr, asn_info.cloned())
                                };

                                let asn_info = asn_info.as_ref();
                                if let Some(last_received_at) = last_received_at {
                                    crate::metrics::packet_jitter(crate::metrics::WRITE, asn_info).set(received_at - last_received_at);
                                }
                                last_received_at = Some(received_at);

                                crate::metrics::packets_total(crate::metrics::WRITE, asn_info).inc();
                                crate::metrics::bytes_total(crate::metrics::WRITE, asn_info).inc_by(size as u64);

                                let timer = crate::metrics::processing_time(crate::metrics::WRITE).start_timer();
                                let result = Self::process_recv_packet(
                                    pool.config.clone(),
                                    &pool.downstream_socket,
                                    recv_addr,
                                    downstream_addr,
                                    &buf[..size],
                                ).await;
                                timer.stop_and_record();
                                if let Err(error) = result {
                                    error.log();
                                    let label = format!("proxy::Session::process_recv_packet: {error}");
                                    crate::metrics::packets_dropped_total(
                                        crate::metrics::WRITE,
                                        &label,
                                        asn_info
                                    ).inc();
                                    crate::metrics::errors_total(crate::metrics::WRITE, &label, asn_info).inc();
                                }
                            }
                        };
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!("Closing upstream socket loop");
                        return;
                    }
                };
            }
        });

        self.create_session_from_existing_socket(key, socket, port, asn_info)
    }

    /// Returns a reference to an existing session mapped to `key`, otherwise
    /// creates a new session either from a fresh socket, or if there are sockets
    /// allocated that are not reserved by an existing destination, using the
    /// existing socket.
    // This uses dynamic dispatch because we're using `parking_lot`, and we
    // to prove that we're not holding a lock across an await point. We're
    // using `parking_lot` because there's no async drop, so we can't lock
    // on drop currently.
    pub fn get<'pool>(
        self: &'pool Arc<Self>,
        key @ SessionKey { dest, .. }: SessionKey,
        asn_info: Option<IpNetEntry>,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<SessionRef<'pool>, super::PipelineError>>
                + Send
                + 'pool,
        >,
    > {
        // If we already have a session for the key pairing, return that session.
        if let Some(entry) = self.session_map.get(&key) {
            return Box::pin(std::future::ready(Ok(entry)));
        }

        // If there's a socket_set available, it means there are sockets
        // allocated to the address that we want to avoid.
        let storage = self.storage.read();
        let Some(socket_set) = storage.destination_to_sockets.get(&dest) else {
            drop(storage);
            return if self.ports_to_sockets.is_empty() {
                // Initial case where we have no allocated or reserved sockets.
                Box::pin(self.create_new_session_from_new_socket(key, asn_info))
            } else {
                // Where we have no allocated sockets for a destination, assign
                // the first available one.
                let entry = self.ports_to_sockets.iter().next().unwrap();
                let port = *entry.key();

                Box::pin(std::future::ready(
                    self.create_session_from_existing_socket(
                        key,
                        entry.value().clone(),
                        port,
                        asn_info,
                    ),
                ))
            };
        };

        if let Some(entry) = self
            .ports_to_sockets
            .iter()
            .find(|entry| !socket_set.contains(entry.key()))
        {
            drop(storage);
            self.storage
                .write()
                .destination_to_sockets
                .get_mut(&dest)
                .unwrap()
                .insert(*entry.key());
            Box::pin(std::future::ready(
                self.create_session_from_existing_socket(
                    key,
                    entry.value().clone(),
                    *entry.key(),
                    asn_info,
                ),
            ))
        } else {
            drop(storage);
            Box::pin(self.create_new_session_from_new_socket(key, asn_info))
        }
    }

    /// Using an existing socket, reserves the socket for a new session.
    fn create_session_from_existing_socket<'session>(
        self: &'session Arc<Self>,
        key: SessionKey,
        upstream_socket: Arc<DualStackLocalSocket>,
        socket_port: u16,
        asn_info: Option<IpNetEntry>,
    ) -> Result<SessionRef<'session>, super::PipelineError> {
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

        if let Some(asn_info) = &asn_info {
            storage
                .sources_to_asn_info
                .insert(key.source, asn_info.clone());
        }

        self.session_map.insert(
            key,
            Session::new(key, upstream_socket, socket_port, self.clone(), asn_info)?,
        );

        Ok(self.session_map.get(&key).unwrap())
    }

    /// process_recv_packet processes a packet that is received by this session.
    async fn process_recv_packet(
        config: Arc<crate::Config>,
        downstream_socket: &Arc<DualStackLocalSocket>,
        source: SocketAddr,
        dest: SocketAddr,
        packet: &[u8],
    ) -> Result<usize, Error> {
        tracing::trace!(%source, %dest, contents = %crate::utils::base64_encode(packet), "received packet from upstream");

        let mut context =
            crate::filters::WriteContext::new(source.into(), dest.into(), packet.to_vec());

        config.filters.load().write(&mut context).await?;

        let packet = context.contents.as_ref();
        tracing::trace!(%source, %dest, contents = %crate::utils::base64_encode(packet), "sending packet downstream");
        downstream_socket
            .send_to(packet, &dest)
            .await
            .map_err(Error::SendTo)
    }

    /// Returns a map of active sessions.
    pub fn sessions(&self) -> &SessionMap {
        &self.session_map
    }

    /// Sends packet data to the appropiate session based on its `key`.
    pub async fn send(
        self: &Arc<Self>,
        mut key: SessionKey,
        asn_info: Option<IpNetEntry>,
        packet: &[u8],
    ) -> Result<usize, super::PipelineError> {
        to_canonical(&mut key.source);
        self.get(key, asn_info)
            .await?
            .send(packet)
            .await
            .map_err(From::from)
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
    fn drop_session(&self, key: SessionKey, session: SessionRef) -> bool {
        drop(session);
        self.session_map.remove(key)
    }

    /// Handles the logic of releasing a socket back into the pool.
    fn release_socket(
        &self,
        SessionKey {
            ref source,
            ref dest,
        }: SessionKey,
        port: u16,
    ) {
        let mut storage = self.storage.write();
        let socket_set = storage.destination_to_sockets.get_mut(dest).unwrap();

        assert!(socket_set.remove(&port));

        if socket_set.is_empty() {
            storage.destination_to_sockets.remove(dest).unwrap();
        }

        let dest_set = storage.sockets_to_destination.get_mut(&port).unwrap();

        assert!(dest_set.remove(dest));

        if dest_set.is_empty() {
            storage.sockets_to_destination.remove(&port).unwrap();
        }

        // Not asserted because the source might not have GeoIP info.
        storage.sources_to_asn_info.remove(source);
        assert!(storage
            .destination_to_sources
            .remove(&(*dest, port))
            .is_some());
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
    socket: Arc<DualStackLocalSocket>,
    /// The GeoIP information of the source.
    asn_info: Option<IpNetEntry>,
    /// The socket pool of the session.
    pool: Arc<SessionPool>,
}

impl Session {
    pub fn new(
        key: SessionKey,
        socket: Arc<DualStackLocalSocket>,
        socket_port: u16,
        pool: Arc<SessionPool>,
        asn_info: Option<IpNetEntry>,
    ) -> Result<Self, super::PipelineError> {
        tracing::debug!(source = %key.source, dest = %key.dest, "Session created");

        let s = Self {
            key,
            socket,
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
        Ok(s)
    }

    pub async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(packet, self.key.dest).await
    }

    fn active_session_metric(&self) -> prometheus::IntGauge {
        metrics::active_sessions(self.asn_info.as_ref())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.active_session_metric().dec();
        metrics::duration_secs().observe(self.created_at.elapsed().as_secs() as f64);
        tracing::debug!(source = %self.key.source, dest_address = %self.key.dest, "Session closed");
        self.pool.release_socket(self.key, self.socket_port);
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
    #[error("failed to send packet downstream: {0}")]
    SendTo(std::io::Error),
    #[error("filter {0}")]
    Filter(#[from] crate::filters::FilterError),
}

impl Loggable for Error {
    fn log(&self) {
        match self {
            Self::SendTo(error) => {
                tracing::error!(kind=%error.kind(), "{}", self)
            }
            Self::Filter(_) => {
                tracing::error!("{}", self);
            }
        }
    }
}

fn to_canonical(addr: &mut SocketAddr) {
    let ip = match addr.ip() {
        std::net::IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                std::net::IpAddr::V4(mapped)
            } else {
                std::net::IpAddr::V6(ip)
            }
        }
        addr => addr,
    };

    addr.set_ip(ip);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{available_addr, AddressType, TestHelper};
    use std::sync::Arc;

    async fn new_pool(config: impl Into<Option<Config>>) -> (Arc<SessionPool>, watch::Sender<()>) {
        let (tx, rx) = watch::channel(());
        (
            SessionPool::new(
                Arc::new(config.into().unwrap_or_default()),
                DualStackLocalSocket::new(
                    crate::test_utils::available_addr(&AddressType::Random)
                        .await
                        .port(),
                )
                .unwrap(),
                rx,
            ),
            tx,
        )
    }

    #[tokio::test]
    async fn insert_and_release_single_socket() {
        let (pool, _sender) = new_pool(None).await;
        let key = (
            (std::net::Ipv4Addr::LOCALHOST, 8080u16).into(),
            (std::net::Ipv4Addr::UNSPECIFIED, 8080u16).into(),
        )
            .into();

        let session = pool.get(key, None).await.unwrap();

        assert!(pool.drop_session(key, session));

        assert!(pool.has_no_allocated_sockets());
    }

    #[tokio::test]
    async fn insert_and_release_multiple_sockets() {
        let (pool, _sender) = new_pool(None).await;
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

        let session1 = pool.get(key1, None).await.unwrap();
        let session2 = pool.get(key2, None).await.unwrap();

        assert!(pool.drop_session(key1, session1));
        assert!(!pool.has_no_allocated_sockets());
        assert!(pool.drop_session(key2, session2));

        assert!(pool.has_no_allocated_sockets());
        drop(pool);
    }

    #[tokio::test]
    async fn same_address_uses_different_sockets() {
        let (pool, _sender) = new_pool(None).await;
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

        let socket1 = pool.get(key1, None).await.unwrap();
        let socket2 = pool.get(key2, None).await.unwrap();

        assert_ne!(socket1.socket_port, socket2.socket_port);
    }

    #[tokio::test]
    async fn different_addresses_uses_same_socket() {
        let (pool, _sender) = new_pool(None).await;
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
        let socket2 = pool.get(key2, None).await.unwrap();

        assert_eq!(socket1.socket_port, socket2.socket_port);
    }

    #[tokio::test]
    async fn spawn_safe_same_destination() {
        let (pool, _sender) = new_pool(None).await;
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
        let (pool, _sender) = new_pool(None).await;
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
        crate::test_utils::map_addr_to_localhost(&mut dest);
        let source = available_addr(&AddressType::Ipv6).await;
        let socket = tokio::net::UdpSocket::bind(source).await.unwrap();
        let mut source = socket.local_addr().unwrap();
        crate::test_utils::map_addr_to_localhost(&mut source);
        let (pool, _sender) = new_pool(None).await;

        let key: SessionKey = (source, dest).into();
        let msg = b"helloworld";

        pool.send(key, None, msg).await.unwrap();

        let mut buf = [0u8; 1024];
        let (size, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            socket.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(msg, &buf[..size]);
    }
}
