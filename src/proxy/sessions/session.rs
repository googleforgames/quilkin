/*
 * Copyright 2020 Google LLC All Rights Reserved.
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
use std::result;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use slog::{debug, error, o, trace, warn, Logger};
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{mpsc, watch, RwLock as TokioRwLock};
use tokio::time::{Duration, Instant};

use crate::cluster::Endpoint;
use crate::extensions::{Filter, FilterChain, UpstreamContext};
use crate::proxy::sessions::error::Error;
use crate::proxy::sessions::metrics::Metrics;
use crate::utils::debug;

type Result<T> = std::result::Result<T, Error>;

/// SESSION_TIMEOUT_SECONDS is the default session timeout - which is one minute.
pub const SESSION_TIMEOUT_SECONDS: u64 = 60;

/// SESSION_EXPIRY_POLL_INTERVAL is the default interval to check for expired sessions.
pub const SESSION_EXPIRY_POLL_INTERVAL: u64 = 60;

/// Session encapsulates a UDP stream session
pub struct Session {
    log: Logger,
    metrics: Metrics,
    chain: Arc<FilterChain>,
    /// created_at is time at which the session was created
    created_at: Instant,
    send: TokioRwLock<SendHalf>,
    /// dest is where to send data to
    dest: Endpoint,
    /// from is the original sender
    from: SocketAddr,
    /// The time at which the session is considered expired and can be removed.
    expiration: Arc<AtomicU64>,
    /// closer is a channel to broadcast on if we are shutting down this Session
    closer: watch::Sender<bool>,
    /// closed is if this Session has closed, and isn't receiving packets anymore
    is_closed: Arc<AtomicBool>,
}

/// ReceivedPacketContext contains state needed to process a received packet.
struct ReceivedPacketContext<'a> {
    packet: &'a [u8],
    chain: Arc<FilterChain>,
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
        chain: Arc<FilterChain>,
        from: SocketAddr,
        dest: Endpoint,
        sender: mpsc::Sender<Packet>,
        ttl: Duration,
    ) -> Result<Self> {
        let log = base
            .new(o!("source" => "proxy::Session", "from" => from, "dest_address" => dest.address));
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let (recv, send) = UdpSocket::bind(addr)
            .await
            .map_err(Error::BindUdpSocket)?
            .split();
        let (closer, closed) = watch::channel::<bool>(false);

        let expiration = Arc::new(AtomicU64::new(0));
        Self::do_update_expiration(&expiration, ttl)?;

        let s = Session {
            metrics,
            log,
            chain,
            send: TokioRwLock::new(send),
            from,
            dest,
            created_at: Instant::now(),
            expiration,
            closer,
            is_closed: Arc::new(AtomicBool::new(false)),
        };
        debug!(s.log, "Session created");

        s.metrics.sessions_total.inc();
        s.metrics.active_sessions.inc();
        s.run(ttl, recv, sender, closed);
        Ok(s)
    }

    /// run starts processing received udp packets on its UdpSocket
    fn run(
        &self,
        ttl: Duration,
        mut recv: RecvHalf,
        mut sender: mpsc::Sender<Packet>,
        mut closed: watch::Receiver<bool>,
    ) {
        let log = self.log.clone();
        let from = self.from;
        let expiration = self.expiration.clone();
        let is_closed = self.is_closed.clone();
        let chain = self.chain.clone();
        let endpoint = self.dest.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            loop {
                debug!(log, "Awaiting incoming packet");
                select! {
                    received = recv.recv_from(&mut buf) => {
                        match received {
                            Err(err) => {
                                metrics.rx_errors_total.inc();
                                error!(log, "Error receiving packet"; "error" => %err);
                            },
                            Ok((size, recv_addr)) => {
                                metrics.rx_bytes_total.inc_by(size as i64);
                                metrics.rx_packets_total.inc();
                                Session::process_recv_packet(
                                    &log,
                                    &metrics,
                                    &mut sender,
                                    &expiration,
                                    ttl,
                                    ReceivedPacketContext {
                                        chain: chain.clone(),
                                        packet: &buf[..size],
                                        endpoint: &endpoint,
                                        from: recv_addr,
                                        to: from,
                                    }).await
                            }
                        };
                    }
                    close_request = closed.recv() => {
                        debug!(log, "Attempting to close session"; "result" => format!("{:?}", close_request));
                        if let Some(true) = close_request {
                            is_closed.store(true, Ordering::Relaxed);
                            debug!(log, "Closing Session");
                            return;
                        } else if close_request.is_none() {
                            is_closed.store(true, Ordering::Relaxed);
                            debug!(log, "Dropping Session");
                            return;
                        }
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
            chain,
            endpoint,
            from,
            to,
        } = packet_ctx;

        trace!(log, "Received packet"; "from" => from,
            "endpoint_addr" => &endpoint.address, 
            "contents" => debug::bytes_to_string(packet.to_vec()));

        if let Err(err) = Session::do_update_expiration(expiration, ttl) {
            warn!(log, "Error updating session expiration"; "error" => %err)
        }

        if let Some(response) =
            chain.on_upstream_receive(UpstreamContext::new(endpoint, from, to, packet.to_vec()))
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
        "contents" => debug::bytes_to_string(buf.to_vec()));

        self.do_send(buf)
            .await
            .map(|size| {
                self.metrics.tx_packets_total.inc();
                self.metrics.tx_bytes_total.inc_by(size as i64);
                Some(size)
            })
            .map_err(|err| {
                self.metrics.tx_errors_total.inc();
                Error::SendToDst(err)
            })
    }

    pub async fn do_send(&self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        let mut send = self.send.write().await;
        send.send_to(buf, &self.dest.address).await
    }

    /// is_closed returns if the Session is closed or not.
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Relaxed)
    }

    /// close closes this Session.
    pub fn close(&self) -> result::Result<(), watch::error::SendError<bool>> {
        debug!(self.log, "Session closed"; "from" => self.from, "dest_address" => &self.dest.address);
        self.closer.broadcast(true)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.metrics.active_sessions.dec();
        self.metrics
            .duration_secs
            .observe(self.created_at.elapsed().as_secs() as f64);
    }
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;

    use prometheus::Registry;
    use slog::info;
    use tokio::time::delay_for;

    use crate::test_utils::{SplitSocket, TestFilter, TestHelper};

    use super::*;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn session_new() {
        let t = TestHelper::default();
        let SplitSocket {
            addr,
            mut recv,
            mut send,
        } = t.create_and_split_socket().await;
        let endpoint = Endpoint::from_address(addr);
        let (send_packet, mut recv_packet) = mpsc::channel::<Packet>(5);

        let sess = Session::new(
            &t.log,
            Metrics::new(&Registry::default(), addr.to_string(), addr.to_string()).unwrap(),
            Arc::new(FilterChain::new(vec![])),
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
        assert!(diff >= 15 && diff <= 20);

        // echo the packet back again
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let (size, recv_addr) = recv.recv_from(&mut buf).await.unwrap();
            assert_eq!("hello", from_utf8(&buf[..size]).unwrap());
            send.send_to(&buf[..size], &recv_addr).await.unwrap();
        });

        sess.send(b"hello").await.unwrap();

        let packet = recv_packet
            .recv()
            .await
            .expect("Should receive a packet 'hello'");
        assert_eq!(String::from("hello").into_bytes(), packet.contents);
        assert_eq!(addr, packet.dest);

        sess.close().unwrap();
    }

    #[tokio::test]
    async fn session_send_to() {
        let t = TestHelper::default();
        let msg = "hello";

        // without a filter
        let (sender, _) = mpsc::channel::<Packet>(1);
        let ep = t.open_socket_and_recv_single_packet().await;
        let endpoint = Endpoint::from_address(ep.addr);

        let session = Session::new(
            &t.log,
            Metrics::new(
                &Registry::default(),
                ep.addr.to_string(),
                ep.addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            ep.addr,
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
    async fn session_close() {
        let t = TestHelper::default();

        let ep = t.open_socket_and_recv_single_packet().await;
        let (send_packet, _) = mpsc::channel::<Packet>(5);
        let endpoint = Endpoint::from_address(ep.addr);

        info!(t.log, ">> creating sessions");
        let sess = Session::new(
            &t.log,
            Metrics::new(
                &Registry::default(),
                ep.addr.to_string(),
                ep.addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            ep.addr,
            endpoint,
            send_packet,
            Duration::from_millis(1000),
        )
        .await
        .unwrap();
        info!(t.log, ">> session created and running");

        assert!(!sess.is_closed(), "session should not be closed");
        sess.close().unwrap();

        // Poll the state to wait for the change, because everything is async
        for _ in 1..1000 {
            let is_closed = sess.is_closed();
            info!(t.log, "session closed?"; "closed" => is_closed);
            if is_closed {
                break;
            }

            delay_for(Duration::from_millis(10)).await;
        }

        assert!(sess.is_closed(), "session should be closed");
    }

    #[tokio::test]
    async fn process_recv_packet() {
        let t = TestHelper::default();

        let chain = Arc::new(FilterChain::new(vec![]));
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
            &Metrics::new(
                &Registry::default(),
                "127.0.1.1:80".parse().unwrap(),
                "127.0.1.1:80".parse().unwrap(),
            )
            .unwrap(),
            &mut sender,
            &expiration,
            Duration::from_secs(10),
            ReceivedPacketContext {
                packet: msg.as_bytes(),
                chain,
                endpoint: &endpoint,
                from: endpoint.address,
                to: dest,
            },
        )
        .await;

        assert!(initial_expiration < expiration.load(Ordering::Relaxed));
        let p = receiver.try_recv().unwrap();
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
        let chain = Arc::new(FilterChain::new(vec![Box::new(TestFilter {})]));
        Session::process_recv_packet(
            &t.log,
            &Metrics::new(
                &Registry::default(),
                "127.0.1.1:80".parse().unwrap(),
                "127.0.1.1:80".parse().unwrap(),
            )
            .unwrap(),
            &mut sender,
            &expiration,
            Duration::from_secs(10),
            ReceivedPacketContext {
                chain,
                packet: msg.as_bytes(),
                endpoint: &endpoint,
                from: endpoint.address,
                to: dest,
            },
        )
        .await;

        assert!(initial_expiration < expiration.load(Ordering::Relaxed));
        let p = receiver.try_recv().unwrap();
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
        let endpoint = Endpoint::from_address(ep.addr);
        let (send_packet, _) = mpsc::channel::<Packet>(5);

        let session = Session::new(
            &t.log,
            Metrics::new(
                &Registry::default(),
                ep.addr.to_string(),
                ep.addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            ep.addr,
            endpoint,
            send_packet,
            Duration::from_secs(10),
        )
        .await
        .unwrap();

        assert_eq!(session.metrics.sessions_total.get(), 1);
        assert_eq!(session.metrics.active_sessions.get(), 1);
        session.close().unwrap();
    }

    #[tokio::test]
    async fn send_to_metrics() {
        let t = TestHelper::default();

        let (sender, _) = mpsc::channel::<Packet>(1);
        let endpoint = t.open_socket_and_recv_single_packet().await;

        let session = Session::new(
            &t.log,
            Metrics::new(
                &Registry::default(),
                endpoint.addr.to_string(),
                endpoint.addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            endpoint.addr,
            Endpoint::from_address(endpoint.addr),
            sender,
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        session.send(b"hello").await.unwrap();
        endpoint.packet_rx.await.unwrap();

        assert_eq!(session.metrics.tx_bytes_total.get(), 5);
        assert_eq!(session.metrics.tx_packets_total.get(), 1);
        session.close().unwrap();
    }

    #[tokio::test]
    async fn session_drop_metrics() {
        let t = TestHelper::default();
        let (send_packet, _) = mpsc::channel::<Packet>(5);
        let endpoint = t.open_socket_and_recv_single_packet().await;

        let session = Session::new(
            &t.log,
            Metrics::new(
                &Registry::default(),
                endpoint.addr.to_string(),
                endpoint.addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            endpoint.addr,
            Endpoint::from_address(endpoint.addr),
            send_packet,
            Duration::from_secs(10),
        )
        .await
        .unwrap();

        assert_eq!(session.metrics.sessions_total.get(), 1);
        assert_eq!(session.metrics.active_sessions.get(), 1);

        let metrics = session.metrics.clone();
        session.close().unwrap();
        drop(session);
        assert_eq!(metrics.sessions_total.get(), 1);
        assert_eq!(metrics.active_sessions.get(), 0);
    }
}
