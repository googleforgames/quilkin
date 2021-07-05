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

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use slog::{debug, error, o, trace, warn, Logger};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{mpsc, watch};
use tokio::time::{Duration, Instant};

use crate::cluster::Endpoint;
use crate::filters::{manager::SharedFilterManager, Filter, WriteContext};
use crate::proxy::sessions::error::Error;
use crate::proxy::sessions::metrics::Metrics;
use crate::utils::debug;

type Result<T> = std::result::Result<T, Error>;

/// Session encapsulates a UDP stream session
pub struct Session {
    log: Logger,
    metrics: Metrics,
    filter_manager: SharedFilterManager,
    /// created_at is time at which the session was created
    created_at: Instant,
    socket: Arc<UdpSocket>,
    /// dest is where to send data to
    dest: Endpoint,
    /// from is the original sender
    from: SocketAddr,
    /// The time at which the session is considered expired and can be removed.
    expiration: Arc<AtomicU64>,
    /// a channel to broadcast on if we are shutting down this Session
    shutdown_tx: watch::Sender<()>,
}

/// ReceivedPacketContext contains state needed to process a received packet.
struct ReceivedPacketContext<'a> {
    packet: &'a [u8],
    filter_manager: SharedFilterManager,
    endpoint: &'a Endpoint,
    from: SocketAddr,
    to: SocketAddr,
}

/// Packet represents a packet that needs to go somewhere
pub struct Packet {
    dest: SocketAddr,
    contents: Vec<u8>,
}

impl Packet {
    pub fn new(dest: SocketAddr, contents: Vec<u8>) -> Packet {
        Packet { dest, contents }
    }

    pub fn dest(&self) -> SocketAddr {
        self.dest
    }

    pub fn contents(&self) -> &Vec<u8> {
        &self.contents
    }
}

impl Session {
    /// new creates a new Session, and starts the process of receiving udp sockets
    /// from its ephemeral port from endpoint(s)
    pub async fn new(
        base: &Logger,
        metrics: Metrics,
        filter_manager: SharedFilterManager,
        from: SocketAddr,
        dest: Endpoint,
        sender: mpsc::Sender<Packet>,
        ttl: Duration,
    ) -> Result<Self> {
        let log = base
            .new(o!("source" => "proxy::Session", "from" => from, "dest_address" => dest.address));
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let socket = Arc::new(UdpSocket::bind(addr).await.map_err(Error::BindUdpSocket)?);
        let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());

        let expiration = Arc::new(AtomicU64::new(0));
        Self::do_update_expiration(&expiration, ttl)?;

        let s = Session {
            metrics,
            log,
            filter_manager,
            socket: socket.clone(),
            from,
            dest,
            created_at: Instant::now(),
            expiration,
            shutdown_tx,
        };
        debug!(s.log, "Session created");

        s.metrics.sessions_total.inc();
        s.metrics.active_sessions.inc();
        s.run(ttl, socket, sender, shutdown_rx);
        Ok(s)
    }

    /// run starts processing received udp packets on its UdpSocket
    fn run(
        &self,
        ttl: Duration,
        socket: Arc<UdpSocket>,
        mut sender: mpsc::Sender<Packet>,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        let log = self.log.clone();
        let from = self.from;
        let expiration = self.expiration.clone();
        let filter_manager = self.filter_manager.clone();
        let endpoint = self.dest.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            loop {
                debug!(log, "Awaiting incoming packet");
                select! {
                    received = socket.recv_from(&mut buf) => {
                        match received {
                            Err(err) => {
                                metrics.rx_errors_total.inc();
                                error!(log, "Error receiving packet"; "error" => %err);
                            },
                            Ok((size, recv_addr)) => {
                                metrics.rx_bytes_total.inc_by(size as u64);
                                metrics.rx_packets_total.inc();
                                Session::process_recv_packet(
                                    &log,
                                    &metrics,
                                    &mut sender,
                                    &expiration,
                                    ttl,
                                    ReceivedPacketContext {
                                        filter_manager: filter_manager.clone(),
                                        packet: &buf[..size],
                                        endpoint: &endpoint,
                                        from: recv_addr,
                                        to: from,
                                    }).await
                            }
                        };
                    }
                    _ = shutdown_rx.changed() => {
                        debug!(log, "Closing Session");
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
    pub fn key(&self) -> (SocketAddr, SocketAddr) {
        (self.from, self.dest.address)
    }

    /// process_recv_packet processes a packet that is received by this session.
    async fn process_recv_packet(
        log: &Logger,
        metrics: &Metrics,
        sender: &mut mpsc::Sender<Packet>,
        expiration: &Arc<AtomicU64>,
        ttl: Duration,
        packet_ctx: ReceivedPacketContext<'_>,
    ) {
        let ReceivedPacketContext {
            packet,
            filter_manager,
            endpoint,
            from,
            to,
        } = packet_ctx;

        trace!(log, "Received packet"; "from" => from,
            "endpoint_addr" => &endpoint.address,
            "contents" => debug::bytes_to_string(&packet));

        if let Err(err) = Session::do_update_expiration(expiration, ttl) {
            warn!(log, "Error updating session expiration"; "error" => %err)
        }

        let filter_chain = {
            let filter_manager_guard = filter_manager.read();
            filter_manager_guard.get_filter_chain()
        };
        if let Some(response) = filter_chain
            .write(WriteContext::new(endpoint, from, to, packet.to_vec()))
            .await
        {
            if let Err(err) = sender.send(Packet::new(to, response.contents)).await {
                metrics.rx_errors_total.inc();
                error!(log, "Error sending packet to channel"; "error" => %err);
            }
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
    pub async fn send(&self, buf: &[u8]) -> Result<Option<usize>> {
        trace!(self.log, "Sending packet";
        "dest_address" => &self.dest.address,
        "contents" => debug::bytes_to_string(buf));

        self.do_send(buf)
            .await
            .map(|size| {
                self.metrics.tx_packets_total.inc();
                self.metrics.tx_bytes_total.inc_by(size as u64);
                Some(size)
            })
            .map_err(|err| {
                self.metrics.tx_errors_total.inc();
                Error::SendToDst(err)
            })
    }

    /// Sends `buf` to the session's destination address. On success, returns
    /// the number of bytes written.
    pub async fn do_send(&self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.socket.send_to(buf, &self.dest.address).await
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.metrics.active_sessions.dec();
        self.metrics
            .duration_secs
            .observe(self.created_at.elapsed().as_secs() as f64);

        if let Err(error) = self.shutdown_tx.send(()) {
            warn!(self.log, "Error sending session shutdown signal"; "error" => error.to_string());
        }

        debug!(self.log, "Session closed"; "from" => self.from, "dest_address" => &self.dest.address);
    }
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{Metrics, Packet, Session};

    use prometheus::Registry;
    use tokio::time::timeout;

    use crate::filters::FilterChain;
    use crate::test_utils::{new_test_chain, TestHelper};

    use crate::cluster::Endpoint;
    use crate::filters::manager::FilterManager;
    use crate::proxy::sessions::session::ReceivedPacketContext;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn session_new() {
        let t = TestHelper::default();
        let socket = t.create_socket().await;
        let addr = socket.local_addr().unwrap();
        let endpoint = Endpoint::from_address(addr);
        let (send_packet, mut recv_packet) = mpsc::channel::<Packet>(5);
        let registry = Registry::default();

        let sess = Session::new(
            &t.log,
            Metrics::new(&registry).unwrap(),
            FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
            addr,
            endpoint,
            send_packet,
            Duration::from_secs(20),
        )
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
        let (sender, _) = mpsc::channel::<Packet>(1);
        let ep = t.open_socket_and_recv_single_packet().await;
        let addr = ep.socket.local_addr().unwrap();
        let endpoint = Endpoint::from_address(addr);
        let registry = Registry::default();

        let session = Session::new(
            &t.log,
            Metrics::new(&Registry::default()).unwrap(),
            FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
            addr,
            endpoint.clone(),
            sender,
            Duration::from_millis(1000),
        )
        .await
        .unwrap();
        session.send(msg.as_bytes()).await.unwrap();
        assert_eq!(msg, ep.packet_rx.await.unwrap());
    }

    #[tokio::test]
    async fn process_recv_packet() {
        let t = TestHelper::default();
        let registry = Registry::default();

        let chain = Arc::new(FilterChain::new(vec![], &registry).unwrap());
        let endpoint = Endpoint::from_address("127.0.1.1:80".parse().unwrap());
        let dest = "127.0.0.1:88".parse().unwrap();
        let (mut sender, mut receiver) = mpsc::channel::<Packet>(10);
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
            &t.log,
            &Metrics::new(&Registry::default()).unwrap(),
            &mut sender,
            &expiration,
            Duration::from_secs(10),
            ReceivedPacketContext {
                packet: msg.as_bytes(),
                filter_manager: FilterManager::fixed(chain),
                endpoint: &endpoint,
                from: endpoint.address,
                to: dest,
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
        let registry = Registry::default();
        let chain = new_test_chain(&registry);
        Session::process_recv_packet(
            &t.log,
            &Metrics::new(&registry).unwrap(),
            &mut sender,
            &expiration,
            Duration::from_secs(10),
            ReceivedPacketContext {
                filter_manager: FilterManager::fixed(chain),
                packet: msg.as_bytes(),
                endpoint: &endpoint,
                from: endpoint.address,
                to: dest,
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
        let addr = ep.socket.local_addr().unwrap();
        let endpoint = Endpoint::from_address(addr);
        let (send_packet, _) = mpsc::channel::<Packet>(5);
        let registry = Registry::default();

        let session = Session::new(
            &t.log,
            Metrics::new(&Registry::default()).unwrap(),
            FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
            addr,
            endpoint,
            send_packet,
            Duration::from_secs(10),
        )
        .await
        .unwrap();

        assert_eq!(session.metrics.sessions_total.get(), 1);
        assert_eq!(session.metrics.active_sessions.get(), 1);
    }

    #[tokio::test]
    async fn send_to_metrics() {
        let t = TestHelper::default();

        let (sender, _) = mpsc::channel::<Packet>(1);
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let addr = endpoint.socket.local_addr().unwrap();
        let registry = Registry::default();
        let session = Session::new(
            &t.log,
            Metrics::new(&registry).unwrap(),
            FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
            addr,
            Endpoint::from_address(addr),
            sender,
            Duration::from_secs(10),
        )
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
        let (send_packet, _) = mpsc::channel::<Packet>(5);
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let addr = endpoint.socket.local_addr().unwrap();
        let registry = Registry::default();
        let session = Session::new(
            &t.log,
            Metrics::new(&registry).unwrap(),
            FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
            addr,
            Endpoint::from_address(addr),
            send_packet,
            Duration::from_secs(10),
        )
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
