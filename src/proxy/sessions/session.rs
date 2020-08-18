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
use std::str::from_utf8;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use slog::{debug, error, o, Logger};
use tokio::io::Result;
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::{mpsc, watch, RwLock};
use tokio::time::{Duration, Instant};

use super::metrics::Metrics;
use crate::config::EndPoint;
use crate::extensions::{Filter, FilterChain};

/// SESSION_TIMEOUT_SECONDS is the default session timeout - which is one minute.
pub const SESSION_TIMEOUT_SECONDS: u64 = 60;

/// Session encapsulates a UDP stream session
pub struct Session {
    log: Logger,
    metrics: Metrics,
    chain: Arc<FilterChain>,
    /// created_at is time at which the session was created
    created_at: Instant,
    send: SendHalf,
    /// dest is where to send data to
    dest: EndPoint,
    /// from is the original sender
    from: SocketAddr,
    /// session expiration timestamp
    expiration: Arc<RwLock<Instant>>,
    /// closer is a channel to broadcast on if we are shutting down this Session
    closer: watch::Sender<bool>,
    /// closed is if this Session has closed, and isn't receiving packets anymore
    is_closed: Arc<AtomicBool>,
}

/// ReceivedPacketContext contains state needed to process a received packet.
struct ReceivedPacketContext<'a> {
    packet: &'a [u8],
    chain: Arc<FilterChain>,
    endpoint: &'a EndPoint,
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
        dest: EndPoint,
        sender: mpsc::Sender<Packet>,
    ) -> Result<Self> {
        let log = base.new(o!("source" => "proxy::Session", "from" => from, "dest_name" => dest.name.clone(), "dest_address" => dest.address));
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let (recv, send) = UdpSocket::bind(addr).await?.split();
        let (closer, closed) = watch::channel::<bool>(false);
        let mut s = Session {
            metrics,
            log,
            chain,
            send,
            from,
            dest,
            created_at: Instant::now(),
            expiration: Arc::new(RwLock::new(
                Instant::now() + Duration::from_secs(SESSION_TIMEOUT_SECONDS),
            )),
            closer,
            is_closed: Arc::new(AtomicBool::new(false)),
        };
        debug!(s.log, "Session created");

        s.metrics.sessions_total.inc();
        s.metrics.active_sessions.inc();
        s.run(recv, sender, closed);
        Ok(s)
    }

    /// run starts processing received udp packets on its UdpSocket
    fn run(
        &mut self,
        mut recv: RecvHalf,
        sender: mpsc::Sender<Packet>,
        mut closed: watch::Receiver<bool>,
    ) {
        let log = self.log.clone();
        let from = self.from;
        let expiration_mtx = self.expiration.clone();
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
                                metrics.errors_total.inc();
                                error!(log, "Error receiving packet"; "error" => %err);
                            },
                            Ok((size, recv_addr)) => {
                                metrics.rx_bytes_total.inc_by(size as i64);
                                metrics.rx_packets_total.inc();
                                Session::process_recv_packet(
                                    &log,
                                    &metrics,
                                    sender.clone(),
                                    expiration_mtx.clone(),
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
                            is_closed.store(true, Relaxed);
                            debug!(log, "Closing Session");
                            return;
                        } else if close_request.is_none() {
                            is_closed.store(true, Relaxed);
                            debug!(log, "Dropping Session");
                            return;
                        }
                    }
                };
            }
        });
    }

    /// expiration returns the current expiration Instant value
    pub async fn expiration(&self) -> Instant {
        *self.expiration.read().await
    }

    /// key returns the key to be used for this session in a SessionMap
    pub fn key(&self) -> (SocketAddr, SocketAddr) {
        (self.from, self.dest.address)
    }

    /// process_recv_packet processes a packet that is received by this session.
    async fn process_recv_packet(
        log: &Logger,
        metrics: &Metrics,
        mut sender: mpsc::Sender<Packet>,
        expiration: Arc<RwLock<Instant>>,
        packet_ctx: ReceivedPacketContext<'_>,
    ) {
        let ReceivedPacketContext {
            packet,
            chain,
            endpoint,
            from,
            to,
        } = packet_ctx;
        debug!(log, "Received packet"; "from" => from, "endpoint_name" => &endpoint.name, "endpoint_addr" => &endpoint.address, "contents" => from_utf8(packet).unwrap());
        Session::inc_expiration(expiration).await;

        if let Some(data) = chain.on_upstream_receive(endpoint, from, to, packet.to_vec()) {
            if let Err(err) = sender.send(Packet::new(to, data)).await {
                metrics.errors_total.inc();
                error!(log, "Error sending packet to channel"; "error" => %err);
            }
        } else {
            metrics.packets_dropped_total.inc();
        }
    }

    /// increment_expiration increments the expiration value by the session timeout
    pub async fn increment_expiration(&mut self) {
        let expiration = self.expiration.clone();
        Session::inc_expiration(expiration).await
    }

    /// increment_expiration increments the expiration value by the session timeout (internal)
    async fn inc_expiration(expiration: Arc<RwLock<Instant>>) {
        let mut expiration = expiration.write().await;
        *expiration = Instant::now() + Duration::from_secs(SESSION_TIMEOUT_SECONDS);
    }

    /// Sends a packet to the Session's dest.
    pub async fn send_to(&mut self, buf: &[u8]) -> Result<Option<usize>> {
        debug!(self.log, "Sending packet"; "dest_name" => &self.dest.name, "dest_address" => &self.dest.address, "contents" => from_utf8(buf).unwrap());

        self.send
            .send_to(buf, &self.dest.address)
            .await
            .map(|size| {
                self.metrics.tx_packets_total.inc();
                self.metrics.tx_bytes_total.inc_by(size as i64);
                Some(size)
            })
            .map_err(|err| {
                self.metrics.errors_total.inc();
                err
            })
    }

    /// is_closed returns if the Session is closed or not.
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Relaxed)
    }

    /// close closes this Session.
    pub fn close(&self) -> result::Result<(), watch::error::SendError<bool>> {
        debug!(self.log, "Session closed"; "from" => self.from, "dest_name" => &self.dest.name, "dest_address" => &self.dest.address);
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
    use prometheus::Registry;
    use slog::info;
    use tokio::time;
    use tokio::time::delay_for;

    use crate::test_utils::{ephemeral_socket, logger, recv_udp, TestFilter};

    use super::*;

    #[tokio::test]
    async fn session_new() {
        time::pause();

        let log = logger();
        let mut socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: local_addr,
            connection_ids: vec![],
        };
        let (send_packet, mut recv_packet) = mpsc::channel::<Packet>(5);

        let mut sess = Session::new(
            &log,
            Metrics::new(
                &Registry::default(),
                local_addr.to_string(),
                local_addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            local_addr,
            endpoint,
            send_packet,
        )
        .await
        .unwrap();

        let initial_expiration: Instant;
        {
            initial_expiration = sess.expiration.read().await.clone();
        }
        let diff = initial_expiration.duration_since(Instant::now());
        assert_eq!(diff.as_secs(), SESSION_TIMEOUT_SECONDS);

        let time_increment = 10;
        time::advance(Duration::from_secs(time_increment)).await;

        // echo the packet back again
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let (size, recv_addr) = socket.recv_from(&mut buf).await.unwrap();
            assert_eq!("hello", from_utf8(&buf[..size]).unwrap());
            socket.send_to(&buf[..size], recv_addr).await.unwrap();
        });

        sess.send_to("hello".as_bytes()).await.unwrap();

        let packet = recv_packet
            .recv()
            .await
            .expect("Should receive a packet 'hello'");
        assert_eq!(String::from("hello").into_bytes(), packet.contents);
        assert_eq!(local_addr, packet.dest);

        let current_expiration = sess.expiration.read().await.clone();
        assert!(Instant::now() < current_expiration);

        let diff = current_expiration.duration_since(initial_expiration);
        info!(log, "difference during test"; "duration" => format!("{:?}", diff));
        assert!(diff.as_secs() >= time_increment);

        sess.close().unwrap();
        time::resume();
    }

    #[tokio::test]
    async fn session_send_to() {
        let log = logger();
        let msg = "hello";

        // without a filter
        let (sender, _) = mpsc::channel::<Packet>(1);
        let (local_addr, wait) = recv_udp().await;
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: local_addr,
            connection_ids: vec![],
        };

        let mut session = Session::new(
            &log,
            Metrics::new(
                &Registry::default(),
                local_addr.to_string(),
                local_addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            local_addr,
            endpoint.clone(),
            sender,
        )
        .await
        .unwrap();
        session.send_to(msg.as_bytes()).await.unwrap();
        assert_eq!(msg, wait.await.unwrap());
    }

    #[tokio::test]
    async fn session_close() {
        let log = logger();
        let socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();
        let (send_packet, _) = mpsc::channel::<Packet>(5);
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: local_addr,
            connection_ids: vec![],
        };

        info!(log, ">> creating sessions");
        let sess = Session::new(
            &log,
            Metrics::new(
                &Registry::default(),
                local_addr.to_string(),
                local_addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            local_addr,
            endpoint,
            send_packet,
        )
        .await
        .unwrap();
        info!(log, ">> session created and running");

        assert!(!sess.is_closed(), "session should not be closed");
        sess.close().unwrap();

        // Poll the state to wait for the change, because everything is async
        for _ in 1..1000 {
            let is_closed = sess.is_closed();
            info!(log, "session closed?"; "closed" => is_closed);
            if is_closed {
                break;
            }

            delay_for(Duration::from_millis(10)).await;
        }

        assert!(sess.is_closed(), "session should be closed");
    }

    #[tokio::test]
    async fn process_recv_packet() {
        let log = logger();
        let chain = Arc::new(FilterChain::new(vec![]));
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: "127.0.1.1:80".parse().unwrap(),
            connection_ids: vec![],
        };
        let dest = "127.0.0.1:88".parse().unwrap();
        let (sender, mut receiver) = mpsc::channel::<Packet>(10);
        let expiration = Arc::new(RwLock::new(Instant::now()));
        let mut initial_expiration: Instant;
        {
            initial_expiration = expiration.read().await.clone();
        }

        // first test with no filtering
        let msg = "hello";
        Session::process_recv_packet(
            &log,
            &Metrics::new(
                &Registry::default(),
                "127.0.1.1:80".parse().unwrap(),
                "127.0.1.1:80".parse().unwrap(),
            )
            .unwrap(),
            sender.clone(),
            expiration.clone(),
            ReceivedPacketContext {
                packet: msg.as_bytes(),
                chain,
                endpoint: &endpoint,
                from: endpoint.address,
                to: dest,
            },
        )
        .await;

        assert!(initial_expiration < *expiration.read().await);
        let p = receiver.try_recv().unwrap();
        assert_eq!(msg, from_utf8(p.contents.as_slice()).unwrap());
        assert_eq!(dest, p.dest);

        {
            initial_expiration = expiration.read().await.clone();
        }
        // add filter
        let chain = Arc::new(FilterChain::new(vec![Box::new(TestFilter {})]));
        Session::process_recv_packet(
            &log,
            &Metrics::new(
                &Registry::default(),
                "127.0.1.1:80".parse().unwrap(),
                "127.0.1.1:80".parse().unwrap(),
            )
            .unwrap(),
            sender.clone(),
            expiration.clone(),
            ReceivedPacketContext {
                chain,
                packet: msg.as_bytes(),
                endpoint: &endpoint,
                from: endpoint.address,
                to: dest,
            },
        )
        .await;

        assert!(initial_expiration < *expiration.read().await);
        let p = receiver.try_recv().unwrap();
        assert_eq!(
            format!(
                "{}:our:{}:{}:{}",
                msg, endpoint.name, endpoint.address, dest
            ),
            from_utf8(p.contents.as_slice()).unwrap()
        );
        assert_eq!(dest, p.dest);
    }

    #[tokio::test]
    async fn session_new_metrics() {
        let log = logger();
        let socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: local_addr,
            connection_ids: vec![],
        };
        let (send_packet, _) = mpsc::channel::<Packet>(5);

        let session = Session::new(
            &log,
            Metrics::new(
                &Registry::default(),
                local_addr.to_string(),
                local_addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            local_addr,
            endpoint,
            send_packet,
        )
        .await
        .unwrap();

        assert_eq!(session.metrics.sessions_total.get(), 1);
        assert_eq!(session.metrics.active_sessions.get(), 1);
        session.close().unwrap();
    }

    #[tokio::test]
    async fn send_to_metrics() {
        let (sender, _) = mpsc::channel::<Packet>(1);
        let (local_addr, wait) = recv_udp().await;

        let mut session = Session::new(
            &logger(),
            Metrics::new(
                &Registry::default(),
                local_addr.to_string(),
                local_addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            local_addr,
            EndPoint {
                name: "endpoint".to_string(),
                address: local_addr,
                connection_ids: vec![],
            },
            sender,
        )
        .await
        .unwrap();
        session.send_to(b"hello").await.unwrap();
        wait.await.unwrap();

        assert_eq!(session.metrics.tx_bytes_total.get(), 5);
        assert_eq!(session.metrics.tx_packets_total.get(), 1);
        session.close().unwrap();
    }

    #[tokio::test]
    async fn session_drop_metrics() {
        let log = logger();
        let socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();
        let endpoint = EndPoint {
            name: "endpoint".to_string(),
            address: local_addr,
            connection_ids: vec![],
        };
        let (send_packet, _) = mpsc::channel::<Packet>(5);

        let session = Session::new(
            &log,
            Metrics::new(
                &Registry::default(),
                local_addr.to_string(),
                local_addr.to_string(),
            )
            .unwrap(),
            Arc::new(FilterChain::new(vec![])),
            local_addr,
            endpoint,
            send_packet,
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
