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

use prometheus::HistogramTimer;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::{
    net::UdpSocket,
    select,
    sync::{mpsc, watch},
    time::{Duration, Instant},
};

use crate::{
    endpoint::{Endpoint, EndpointAddress},
    filters::{Filter, SharedFilterChain, WriteContext},
    proxy::{
        server::metrics::Metrics as ProxyMetrics,
        sessions::{error::Error, metrics::Metrics},
    },
    utils::debug,
};

type Result<T> = std::result::Result<T, Error>;

/// Session encapsulates a UDP stream session
pub struct Session {
    metrics: Metrics,
    proxy_metrics: ProxyMetrics,
    filter_chain: SharedFilterChain,
    /// created_at is time at which the session was created
    created_at: Instant,
    socket: Arc<UdpSocket>,
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
    filter_chain: SharedFilterChain,
    endpoint: &'a Endpoint,
    source: EndpointAddress,
    dest: EndpointAddress,
    timer: HistogramTimer,
}

/// Represents a data packet received by an Endpoint to this Session.
pub struct UpstreamPacket {
    dest: EndpointAddress,
    contents: Vec<u8>,
    timer: HistogramTimer,
}

impl UpstreamPacket {
    pub fn new(dest: EndpointAddress, contents: Vec<u8>, timer: HistogramTimer) -> UpstreamPacket {
        UpstreamPacket {
            dest,
            contents,
            timer,
        }
    }

    pub fn dest(&self) -> &EndpointAddress {
        &self.dest
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    /// stop and record the stored [HistogramTimer]
    pub fn stop_and_record(self) {
        self.timer.stop_and_record();
    }
}

pub struct SessionArgs {
    pub metrics: Metrics,
    pub proxy_metrics: ProxyMetrics,
    pub filter_chain: SharedFilterChain,
    pub source: EndpointAddress,
    pub dest: Endpoint,
    pub sender: mpsc::Sender<UpstreamPacket>,
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
    async fn new(args: SessionArgs) -> Result<Self> {
        let addr = (std::net::Ipv4Addr::UNSPECIFIED, 0);
        let socket = Arc::new(UdpSocket::bind(addr).await.map_err(Error::BindUdpSocket)?);
        let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());

        let expiration = Arc::new(AtomicU64::new(0));
        Self::do_update_expiration(&expiration, args.ttl)?;

        let s = Session {
            metrics: args.metrics,
            proxy_metrics: args.proxy_metrics,
            filter_chain: args.filter_chain,
            socket: socket.clone(),
            source: args.source,
            dest: args.dest,
            created_at: Instant::now(),
            expiration,
            shutdown_tx,
        };

        tracing::debug!(source = %s.source, dest = ?s.dest, "Session created");

        s.metrics.sessions_total.inc();
        s.metrics.active_sessions.inc();
        s.run(args.ttl, socket, args.sender, shutdown_rx);
        Ok(s)
    }

    /// run starts processing received udp packets on its UdpSocket
    fn run(
        &self,
        ttl: Duration,
        socket: Arc<UdpSocket>,
        mut sender: mpsc::Sender<UpstreamPacket>,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        let source = self.source.clone();
        let expiration = self.expiration.clone();
        let filter_chain = self.filter_chain.clone();
        let endpoint = self.dest.clone();
        let metrics = self.metrics.clone();
        let proxy_metrics = self.proxy_metrics.clone();
        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            loop {
                tracing::debug!(source = %source, dest = ?endpoint, "Awaiting incoming packet");

                select! {
                    received = socket.recv_from(&mut buf) => {
                        match received {
                            Err(error) => {
                                metrics.rx_errors_total.inc();
                                tracing::error!(%error, %source, dest = ?endpoint, "Error receiving packet");
                            },
                            Ok((size, recv_addr)) => {
                                metrics.rx_bytes_total.inc_by(size as u64);
                                metrics.rx_packets_total.inc();
                                Session::process_recv_packet(
                                    &metrics,
                                    &mut sender,
                                    &expiration,
                                    ttl,
                                    ReceivedPacketContext {
                                        filter_chain: filter_chain.clone(),
                                        packet: &buf[..size],
                                        endpoint: &endpoint,
                                        source: recv_addr.into(),
                                        dest: source.clone(),
                                        timer: proxy_metrics.write_processing_time_seconds.start_timer(),
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
        self.expiration.load(std::sync::atomic::Ordering::Relaxed)
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
        metrics: &Metrics,
        sender: &mut mpsc::Sender<UpstreamPacket>,
        expiration: &Arc<AtomicU64>,
        ttl: Duration,
        packet_ctx: ReceivedPacketContext<'_>,
    ) {
        let ReceivedPacketContext {
            packet,
            filter_chain,
            endpoint,
            source: from,
            dest: to,
            timer,
        } = packet_ctx;

        tracing::trace!(%from, dest = %endpoint.address, contents = %debug::bytes_to_string(packet), "Received packet");

        if let Err(error) = Session::do_update_expiration(expiration, ttl) {
            tracing::warn!(%error, "Error updating session expiration")
        }

        let write_result: futures::future::OptionFuture<_> = filter_chain
            .write(WriteContext::new(
                endpoint,
                from,
                to.clone(),
                packet.to_vec(),
            ))
            .map(|response| sender.send(UpstreamPacket::new(to, response.contents, timer)))
            .into();

        if let Some(Err(error)) = write_result.await {
            metrics.rx_errors_total.inc();
            tracing::error!(%error, "Error sending packet to channel");
        } else {
            metrics.packets_dropped_total.inc();
        }
    }

    /// update_expiration set the increments the expiration value by the session timeout
    pub fn update_expiration(&self, ttl: Duration) -> Result<()> {
        Self::do_update_expiration(&self.expiration, ttl)
    }

    /// do_update_expiration increments the expiration value by the session timeout (internal)
    fn do_update_expiration(expiration: &Arc<AtomicU64>, ttl: Duration) -> Result<()> {
        let new_expiration_time = SystemTime::now()
            .checked_add(ttl)
            .ok_or_else(|| {
                Error::UpdateSessionExpiration(format!(
                    "checked_add error: expiration ttl {:?} is out of bounds",
                    ttl
                ))
            })?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                Error::UpdateSessionExpiration(
                    "duration_since was called with time later than the current time".into(),
                )
            })?
            .as_secs();

        expiration.store(new_expiration_time, Ordering::Relaxed);

        Ok(())
    }

    /// Sends a packet to the Session's dest.
    pub async fn send(&self, buf: &[u8]) -> crate::Result<Option<usize>> {
        tracing::trace!(
        dest_address = %self.dest.address,
        contents = %debug::bytes_to_string(buf),
        "Sending packet");

        self.do_send(buf)
            .await
            .map(|size| {
                self.metrics.tx_packets_total.inc();
                self.metrics.tx_bytes_total.inc_by(size as u64);
                Some(size)
            })
            .map_err(|err| {
                self.metrics.tx_errors_total.inc();
                eyre::eyre!(err).wrap_err("Error sending to destination.")
            })
    }

    /// Sends `buf` to the session's destination address. On success, returns
    /// the number of bytes written.
    pub async fn do_send(&self, buf: &[u8]) -> crate::Result<usize> {
        self.socket
            .send_to(buf, &self.dest.address.to_socket_addr()?)
            .await
            .map_err(|error| eyre::eyre!(error))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.metrics.active_sessions.dec();
        self.metrics
            .duration_secs
            .observe(self.created_at.elapsed().as_secs() as f64);

        if let Err(error) = self.shutdown_tx.send(()) {
            tracing::warn!(%error, "Error sending session shutdown signal");
        }

        tracing::debug!(source = %self.source, dest_address = %self.dest.address, "Session closed");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        str::from_utf8,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use super::{Metrics, ProxyMetrics, Session, UpstreamPacket};

    use prometheus::{Histogram, HistogramOpts};
    use tokio::time::timeout;

    use crate::test_utils::{new_test_chain, TestHelper};

    use crate::endpoint::{Endpoint, EndpointAddress};
    use crate::filters::SharedFilterChain;
    use crate::proxy::sessions::session::{ReceivedPacketContext, SessionArgs};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn session_new() {
        let t = TestHelper::default();
        let socket = t.create_socket().await;
        let addr: EndpointAddress = socket.local_addr().unwrap().into();
        let endpoint = Endpoint::new(addr.clone());
        let (send_packet, mut recv_packet) = mpsc::channel::<UpstreamPacket>(5);

        let sess = Session::new(SessionArgs {
            metrics: Metrics::new().unwrap(),
            proxy_metrics: ProxyMetrics::new().unwrap(),
            filter_chain: SharedFilterChain::empty(),
            source: addr.clone(),
            dest: endpoint,
            sender: send_packet,
            ttl: Duration::from_secs(20),
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

        // echo the packet back again
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let (size, recv_addr) = socket.recv_from(&mut buf).await.unwrap();
            assert_eq!("hello", from_utf8(&buf[..size]).unwrap());
            socket.send_to(&buf[..size], &recv_addr).await.unwrap();
        });

        sess.send(b"hello").await.unwrap();

        let packet = recv_packet
            .recv()
            .await
            .expect("Should receive a packet 'hello'");
        assert_eq!(String::from("hello").into_bytes(), packet.contents);
        assert_eq!(addr, packet.dest);
    }

    #[tokio::test]
    async fn session_send_to() {
        let t = TestHelper::default();
        let msg = "hello";

        // without a filter
        let (sender, _) = mpsc::channel::<UpstreamPacket>(1);
        let ep = t.open_socket_and_recv_single_packet().await;
        let addr: EndpointAddress = ep.socket.local_addr().unwrap().into();
        let endpoint = Endpoint::new(addr.clone());

        let session = Session::new(SessionArgs {
            metrics: Metrics::new().unwrap(),
            proxy_metrics: ProxyMetrics::new().unwrap(),
            filter_chain: SharedFilterChain::empty(),
            source: addr,
            dest: endpoint.clone(),
            sender,
            ttl: Duration::from_millis(1000),
        })
        .await
        .unwrap();
        session.send(msg.as_bytes()).await.unwrap();
        assert_eq!(msg, ep.packet_rx.await.unwrap());
    }

    #[tokio::test]
    async fn process_recv_packet() {
        let histogram = Histogram::with_opts(HistogramOpts::new("test", "test")).unwrap();

        let endpoint = Endpoint::new("127.0.1.1:80".parse().unwrap());
        let dest: EndpointAddress = (Ipv4Addr::LOCALHOST, 88).into();
        let (mut sender, mut receiver) = mpsc::channel::<UpstreamPacket>(10);
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
            &Metrics::new().unwrap(),
            &mut sender,
            &expiration,
            Duration::from_secs(10),
            ReceivedPacketContext {
                packet: msg.as_bytes(),
                filter_chain: crate::filters::SharedFilterChain::empty(),
                endpoint: &endpoint,
                source: endpoint.address.clone(),
                dest: dest.clone(),
                timer: histogram.start_timer(),
            },
        )
        .await;

        assert!(initial_expiration < expiration.load(Ordering::Relaxed));
        let p = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("Should receive a packet")
            .unwrap();
        assert_eq!(msg, from_utf8(p.contents.as_slice()).unwrap());
        assert_eq!(dest, p.dest);

        let expiration = Arc::new(AtomicU64::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ));
        let initial_expiration = expiration.load(Ordering::Relaxed);
        // add filter
        let filter_chain = new_test_chain();
        Session::process_recv_packet(
            &Metrics::new().unwrap(),
            &mut sender,
            &expiration,
            Duration::from_secs(10),
            ReceivedPacketContext {
                filter_chain,
                packet: msg.as_bytes(),
                endpoint: &endpoint,
                source: endpoint.address.clone(),
                dest: dest.clone(),
                timer: histogram.start_timer(),
            },
        )
        .await;

        assert!(initial_expiration < expiration.load(Ordering::Relaxed));
        let p = timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("Should receive a packet")
            .unwrap();
        assert_eq!(
            format!("{}:our:{}:{}", msg, endpoint.address, dest),
            from_utf8(p.contents.as_slice()).unwrap()
        );
        assert_eq!(dest, p.dest);
    }

    #[tokio::test]
    async fn session_new_metrics() {
        let t = TestHelper::default();
        let ep = t.open_socket_and_recv_single_packet().await;
        let addr: EndpointAddress = ep.socket.local_addr().unwrap().into();
        let endpoint = Endpoint::new(addr.clone());
        let (send_packet, _) = mpsc::channel::<UpstreamPacket>(5);

        let session = Session::new(SessionArgs {
            metrics: Metrics::new().unwrap(),
            proxy_metrics: ProxyMetrics::new().unwrap(),
            filter_chain: SharedFilterChain::empty(),
            source: addr,
            dest: endpoint,
            sender: send_packet,
            ttl: Duration::from_secs(10),
        })
        .await
        .unwrap();

        assert_eq!(session.metrics.sessions_total.get(), 1);
        assert_eq!(session.metrics.active_sessions.get(), 1);
    }

    #[tokio::test]
    async fn send_to_metrics() {
        let t = TestHelper::default();

        let (sender, _) = mpsc::channel::<UpstreamPacket>(1);
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let addr: EndpointAddress = endpoint.socket.local_addr().unwrap().into();
        let session = Session::new(SessionArgs {
            metrics: Metrics::new().unwrap(),
            proxy_metrics: ProxyMetrics::new().unwrap(),
            filter_chain: SharedFilterChain::empty(),
            source: addr.clone(),
            dest: Endpoint::new(addr),
            sender,
            ttl: Duration::from_secs(10),
        })
        .await
        .unwrap();
        session.send(b"hello").await.unwrap();
        endpoint.packet_rx.await.unwrap();

        assert_eq!(session.metrics.tx_bytes_total.get(), 5);
        assert_eq!(session.metrics.tx_packets_total.get(), 1);
    }

    #[tokio::test]
    async fn session_drop_metrics() {
        let t = TestHelper::default();
        let (send_packet, _) = mpsc::channel::<UpstreamPacket>(5);
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let addr: EndpointAddress = endpoint.socket.local_addr().unwrap().into();
        let session = Session::new(SessionArgs {
            metrics: Metrics::new().unwrap(),
            proxy_metrics: ProxyMetrics::new().unwrap(),
            filter_chain: SharedFilterChain::empty(),
            source: addr.clone(),
            dest: Endpoint::new(addr),
            sender: send_packet,
            ttl: Duration::from_secs(10),
        })
        .await
        .unwrap();

        assert_eq!(session.metrics.sessions_total.get(), 1);
        assert_eq!(session.metrics.active_sessions.get(), 1);

        let metrics = session.metrics.clone();
        drop(session);
        assert_eq!(metrics.sessions_total.get(), 1);
        assert_eq!(metrics.active_sessions.get(), 0);
    }
}
