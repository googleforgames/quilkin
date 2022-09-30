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

pub(crate) mod manager;
pub(crate) mod metrics;

pub use manager::SESSION_TIMEOUT_SECONDS;

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use prometheus::HistogramTimer;
use tokio::{
    net::UdpSocket,
    select,
    sync::watch,
    time::{Duration, Instant},
};

use crate::{
    endpoint::{Endpoint, EndpointAddress},
    filters::{Filter, WriteContext},
    utils::{debug, Loggable},
};

type Result<T> = std::result::Result<T, Error>;

/// Session encapsulates a UDP stream session
pub struct Session {
    config: Arc<crate::Config>,
    /// created_at is time at which the session was created
    created_at: Instant,
    /// socket that sends and receives from and to the endpoint address
    upstream_socket: Arc<UdpSocket>,
    /// dest is where to send data to
    dest: Endpoint,
    /// address of original sender
    source: EndpointAddress,
    /// The time at which the session is considered expired and can be removed.
    expiration: Arc<AtomicU64>,
    /// a channel to broadcast on if we are shutting down this Session
    shutdown_tx: watch::Sender<()>,
}

// A (source, destination) address pair that uniquely identifies a session.
#[derive(Clone, Eq, Hash, PartialEq, Debug, PartialOrd, Ord)]
pub struct SessionKey {
    pub source: EndpointAddress,
    pub dest: EndpointAddress,
}

impl From<(EndpointAddress, EndpointAddress)> for SessionKey {
    fn from((source, dest): (EndpointAddress, EndpointAddress)) -> Self {
        SessionKey { source, dest }
    }
}

/// ReceivedPacketContext contains state needed to process a received packet.
struct ReceivedPacketContext<'a> {
    packet: &'a [u8],
    config: Arc<crate::Config>,
    endpoint: &'a Endpoint,
    source: EndpointAddress,
    dest: EndpointAddress,
    timer: HistogramTimer,
}

pub struct SessionArgs {
    pub config: Arc<crate::Config>,
    pub source: EndpointAddress,
    pub downstream_socket: Arc<UdpSocket>,
    pub dest: Endpoint,
    pub ttl: Duration,
}

impl SessionArgs {
    /// Creates a new Session, and starts the process of receiving udp sockets
    /// from its ephemeral port from endpoint(s)
    pub async fn into_session(self) -> Result<Session> {
        Session::new(self).await
    }
}

impl Session {
    /// internal constructor for a Session from SessionArgs
    #[tracing::instrument(skip_all)]
    async fn new(args: SessionArgs) -> Result<Self> {
        let addr = (std::net::Ipv4Addr::UNSPECIFIED, 0);
        let upstream_socket = Arc::new(UdpSocket::bind(addr).await.map_err(Error::BindUdpSocket)?);
        upstream_socket
            .connect(
                args.dest
                    .address
                    .to_socket_addr()
                    .map_err(Error::ToSocketAddr)?,
            )
            .await
            .map_err(Error::BindUdpSocket)?;
        let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());

        let expiration = Arc::new(AtomicU64::new(0));
        Self::do_update_expiration(&expiration, args.ttl)?;

        let s = Session {
            config: args.config.clone(),
            upstream_socket,
            source: args.source,
            dest: args.dest,
            created_at: Instant::now(),
            expiration,
            shutdown_tx,
        };
        tracing::debug!(source = %s.source, dest = ?s.dest, "Session created");

        self::metrics::TOTAL_SESSIONS.inc();
        self::metrics::ACTIVE_SESSIONS.inc();
        s.run(args.ttl, args.downstream_socket, shutdown_rx);
        Ok(s)
    }

    /// run starts processing receiving upstream udp packets
    /// and sending them back downstream
    fn run(
        &self,
        ttl: Duration,
        downstream_socket: Arc<UdpSocket>,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        let source = self.source.clone();
        let expiration = self.expiration.clone();
        let config = self.config.clone();
        let endpoint = self.dest.clone();
        let upstream_socket = self.upstream_socket.clone();

        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            loop {
                tracing::debug!(source = %source, dest = ?endpoint, "Awaiting incoming packet");

                select! {
                    received = upstream_socket.recv_from(&mut buf) => {
                        match received {
                            Err(error) => {
                                crate::metrics::ERRORS_TOTAL.with_label_values(&[crate::metrics::WRITE_DIRECTION_LABEL]).inc();
                                tracing::error!(%error, %source, dest = ?endpoint, "Error receiving packet");
                            },
                            Ok((size, recv_addr)) => {
                                crate::metrics::PACKETS_SIZE.with_label_values(&[crate::metrics::WRITE_DIRECTION_LABEL]).inc_by(size as f64);
                                crate::metrics::PACKETS_TOTAL.with_label_values(&[crate::metrics::WRITE_DIRECTION_LABEL]).inc();
                                Session::process_recv_packet(
                                    &downstream_socket,
                                    &expiration,
                                    ttl,
                                    ReceivedPacketContext {
                                        config: config.clone(),
                                        packet: &buf[..size],
                                        endpoint: &endpoint,
                                        source: recv_addr.into(),
                                        dest: source.clone(),
                                        timer: crate::metrics::PROCESSING_TIME.with_label_values(&[crate::metrics::WRITE_DIRECTION_LABEL]).start_timer(),
                                    }).await
                            }
                        };
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!(%source, dest = ?endpoint, "Closing Session");
                        return;
                    }
                };
            }
        });
    }

    /// expiration returns the current expiration Instant value
    pub fn expiration(&self) -> u64 {
        self.expiration.load(Ordering::Relaxed)
    }

    /// key returns the key to be used for this session in a SessionMap
    pub fn key(&self) -> SessionKey {
        SessionKey {
            source: self.source.clone(),
            dest: self.dest.address.clone(),
        }
    }

    /// process_recv_packet processes a packet that is received by this session.
    async fn process_recv_packet(
        downstream_socket: &Arc<UdpSocket>,
        expiration: &Arc<AtomicU64>,
        ttl: Duration,
        packet_ctx: ReceivedPacketContext<'_>,
    ) {
        let ReceivedPacketContext {
            packet,
            config,
            endpoint,
            source: from,
            dest,
            timer,
        } = packet_ctx;

        tracing::trace!(%from, dest = %endpoint.address, contents = %debug::bytes_to_string(packet), "received packet from upstream");

        let result = Session::do_update_expiration(expiration, ttl)
            .and_then(|_| {
                config
                    .filters
                    .load()
                    .write(WriteContext::new(
                        endpoint,
                        from.clone(),
                        dest.clone(),
                        packet.to_vec(),
                    ))
                    .ok_or(Error::FilterDroppedPacket)
            })
            .and_then(|response| {
                dest.to_socket_addr()
                    .map(|addr| (addr, response))
                    .map_err(Error::ToSocketAddr)
            });

        let handle_error = |error: Error| {
            error.log();
            crate::metrics::PACKETS_DROPPED
                .with_label_values(&[crate::metrics::WRITE_DIRECTION_LABEL])
                .inc();
            crate::metrics::ERRORS_TOTAL
                .with_label_values(&[crate::metrics::WRITE_DIRECTION_LABEL])
                .inc();
        };

        match result {
            Ok((addr, response)) => {
                let packet = response.contents.as_slice();
                tracing::trace!(%from, dest = %addr, contents = %debug::bytes_to_string(packet), "sending packet downstream");
                let _ = downstream_socket
                    .send_to(packet, addr)
                    .await
                    .map_err(Error::SendTo)
                    .map_err(handle_error);
            }
            Err(error) => (handle_error)(error),
        };

        timer.stop_and_record();
    }

    /// update_expiration set the increments the expiration value by the session timeout
    pub fn update_expiration(&self, ttl: Duration) -> Result<()> {
        Self::do_update_expiration(&self.expiration, ttl)
    }

    /// do_update_expiration increments the expiration value by the session timeout (internal)
    fn do_update_expiration(expiration: &Arc<AtomicU64>, ttl: Duration) -> Result<()> {
        let now = SystemTime::now();
        let new_expiration_time = now
            .checked_add(ttl)
            .ok_or(Error::UpdateSessionExpiration { now, ttl })?
            .duration_since(UNIX_EPOCH)
            // This is safe because it's impossible for `UNIX_EPOCH` to be
            // ahead of any clock time, or the system we're on is so severely
            // broken that the expiration code isn't going to work anyway.
            .unwrap();

        expiration.store(new_expiration_time.as_secs(), Ordering::Relaxed);

        Ok(())
    }

    /// Sends a packet to the Session's dest.
    pub async fn send(&self, buf: &[u8], ttl: Duration) {
        tracing::trace!(
        dest_address = %self.dest.address,
        contents = %debug::bytes_to_string(buf),
        "sending packet upstream");

        match self.do_send(buf).await {
            Ok(size) => {
                crate::metrics::PACKETS_TOTAL
                    .with_label_values(&[crate::metrics::READ_DIRECTION_LABEL])
                    .inc();
                crate::metrics::BYTES_TOTAL
                    .with_label_values(&[crate::metrics::READ_DIRECTION_LABEL])
                    .inc_by(size as u64);
            }
            Err(error) => {
                crate::metrics::PACKETS_DROPPED
                    .with_label_values(&[crate::metrics::READ_DIRECTION_LABEL])
                    .inc();
                crate::metrics::ERRORS_TOTAL
                    .with_label_values(&[crate::metrics::READ_DIRECTION_LABEL])
                    .inc();
                tracing::error!(kind=%error.kind(), "{}", error);
                return;
            }
        }

        if let Err(error) = self.update_expiration(ttl) {
            tracing::warn!(%error, "Error updating session expiration")
        }
    }

    /// Sends `buf` to the session's destination address. On success, returns
    /// the number of bytes written.
    pub async fn do_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.upstream_socket.send(buf).await
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        metrics::ACTIVE_SESSIONS.dec();
        metrics::DURATION_SECS.observe(self.created_at.elapsed().as_secs() as f64);

        if let Err(error) = self.shutdown_tx.send(()) {
            tracing::warn!(%error, "Error sending session shutdown signal");
        }

        tracing::debug!(source = %self.source, dest_address = %self.dest.address, "Session closed");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to bind socket: {0}")]
    BindUdpSocket(std::io::Error),
    #[error("{} + {}s would have caused overflow", chrono::DateTime::<chrono::Utc>::from(*.now).to_rfc2822(), .ttl.as_secs())]
    UpdateSessionExpiration {
        now: std::time::SystemTime,
        ttl: std::time::Duration,
    },
    #[error("failed to convert endpoint to socket address: {0}")]
    ToSocketAddr(crate::endpoint::ToSocketAddrError),
    #[error("failed to send packet downstream: {0}")]
    SendTo(std::io::Error),
    #[error("filter dropped packet from upstream")]
    FilterDroppedPacket,
}

impl Loggable for Error {
    fn log(&self) {
        match self {
            Self::BindUdpSocket(error) | Self::SendTo(error) => {
                tracing::error!(kind=%error.kind(), "{}", self)
            }
            Self::UpdateSessionExpiration { .. } | Self::ToSocketAddr(_) => {
                tracing::error!("{}", self)
            }
            Self::FilterDroppedPacket => {
                tracing::trace!("{}", self)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        str::from_utf8,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::*;

    use prometheus::{Histogram, HistogramOpts};
    use tokio::time::timeout;

    use crate::{
        endpoint::{Endpoint, EndpointAddress},
        proxy::sessions::{ReceivedPacketContext, SessionArgs},
        test_utils::{create_socket, new_test_config, TestHelper},
    };

    #[tokio::test]
    async fn session_send_and_receive() {
        let mut t = TestHelper::default();
        let addr = t.run_echo_server().await;
        let endpoint = Endpoint::new(addr.clone());
        let socket = Arc::new(create_socket().await);
        let msg = "hello";
        let ttl = Duration::from_secs(20);

        let sess = Session::new(SessionArgs {
            config: <_>::default(),
            source: addr.clone(),
            downstream_socket: socket.clone(),
            dest: endpoint,
            ttl,
        })
        .await
        .unwrap();

        let initial_expiration_secs = sess.expiration.load(Ordering::Relaxed);
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let diff = initial_expiration_secs - now_secs;
        assert!((15..21).contains(&diff));

        sess.send(msg.as_bytes(), ttl).await;

        let mut buf = vec![0; 1024];
        let (size, recv_addr) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = &buf[..size];
        assert_eq!(msg, from_utf8(packet).unwrap());
        assert_eq!(addr.port(), recv_addr.port());
    }

    #[tokio::test]
    async fn process_recv_packet() {
        crate::test_utils::load_test_filters();
        let histogram = Histogram::with_opts(HistogramOpts::new("test", "test")).unwrap();

        let socket = Arc::new(create_socket().await);
        let endpoint = Endpoint::new("127.0.1.1:80".parse().unwrap());
        let dest: EndpointAddress = socket.local_addr().unwrap().into();
        let expiration = Arc::new(AtomicU64::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ));
        let initial_expiration = expiration.load(Ordering::Relaxed);

        // first test with no filtering
        let msg = "hello";
        Session::process_recv_packet(
            &socket,
            &expiration,
            Duration::from_secs(10),
            ReceivedPacketContext {
                config: <_>::default(),
                packet: msg.as_bytes(),
                endpoint: &endpoint,
                source: endpoint.address.clone(),
                dest: dest.clone(),
                timer: histogram.start_timer(),
            },
        )
        .await;

        assert!(initial_expiration < expiration.load(Ordering::Relaxed));

        let mut buf = vec![0; 1024];
        let (size, recv_addr) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("Should receive a packet")
            .unwrap();
        assert_eq!(msg, from_utf8(&buf[..size]).unwrap());
        assert_eq!(dest.port(), recv_addr.port());

        let expiration = Arc::new(AtomicU64::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ));
        let initial_expiration = expiration.load(Ordering::Relaxed);
        // add filter
        let config = Arc::new(new_test_config());
        Session::process_recv_packet(
            &socket,
            &expiration,
            Duration::from_secs(10),
            ReceivedPacketContext {
                config,
                packet: msg.as_bytes(),
                endpoint: &endpoint,
                source: endpoint.address.clone(),
                dest: dest.clone(),
                timer: histogram.start_timer(),
            },
        )
        .await;

        assert!(initial_expiration < expiration.load(Ordering::Relaxed));
        let (size, recv_addr) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("Should receive a packet")
            .unwrap();
        assert_eq!(
            format!("{}:our:{}:{}", msg, endpoint.address, dest),
            from_utf8(&buf[..size]).unwrap()
        );
        assert_eq!(dest.port(), recv_addr.port());
    }
}
