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

/// SESSION_TIMEOUT_SECONDS is the default session timeout - which is one minute.
pub const SESSION_TIMEOUT_SECONDS: u64 = 60;

/// Packet represents a packet that needs to go somewhere
pub struct Packet {
    dest: SocketAddr,
    contents: Vec<u8>,
}

/// Session encapsulates a UDP stream session
pub struct Session {
    log: Logger,
    send: SendHalf,
    /// dest is where to send data to
    dest: SocketAddr,
    /// from is the original sender
    from: SocketAddr,
    /// session expiration timestamp
    expiration: Arc<RwLock<Instant>>,
    /// closer is a channel to broadcast on if we are shutting down this Session
    closer: watch::Sender<bool>,
    /// closed is if this Session has closed, and isn't receiving packets anymore
    is_closed: Arc<AtomicBool>,
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
        from: SocketAddr,
        dest: SocketAddr,
        sender: mpsc::Sender<Packet>,
    ) -> Result<Self> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        let (recv, send) = UdpSocket::bind(addr).await?.split();
        let (closer, closed) = watch::channel::<bool>(false);
        let mut s = Session {
            log: base.new(o!("source" => "server::Session", "from" => from, "dest" => dest)),
            send,
            from,
            dest,
            expiration: Arc::new(RwLock::new(
                Instant::now() + Duration::from_secs(SESSION_TIMEOUT_SECONDS),
            )),
            closer,
            is_closed: Arc::new(AtomicBool::new(false)),
        };
        debug!(s.log, "Session created");

        s.run(recv, sender, closed);
        Ok(s)
    }

    /// run starts processing received udp packets on its UdpSocket
    fn run(
        &mut self,
        mut recv: RecvHalf,
        sender: mpsc::Sender<Packet>,
        closed: watch::Receiver<bool>,
    ) {
        let log = self.log.clone();
        let from = self.from;
        let expiration_mtx = self.expiration.clone();
        let mut closed = Box::new(closed);
        let is_closed = self.is_closed.clone();
        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            loop {
                debug!(log, "Awaiting incoming packet");
                select! {
                    received = recv.recv_from(&mut buf) => {
                        match received {
                            Err(err) => error!(log, "Error receiving packet"; "error" => %err),
                            Ok((size, recv_addr)) => Session::process_recv_packet(
                                &log,
                                &buf[..size],
                                recv_addr,
                                from,
                                sender.clone(),
                                expiration_mtx.clone()).await,
                        };
                    }
                    close_request = closed.recv() => {
                        debug!(log, "Attempting to close session"; "result" => format!("{:?}", close_request));
                        if let Some(true) = close_request {
                            is_closed.store(true, Relaxed);
                            debug!(log, "Closing Session");
                            return;
                        } else if let None = close_request {
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
        (self.from, self.dest)
    }

    /// process_recv_packet processes a packet that is received by this session.
    async fn process_recv_packet(
        log: &Logger,
        packet: &[u8],
        from: SocketAddr,
        dest: SocketAddr,
        mut sender: mpsc::Sender<Packet>,
        expiration: Arc<RwLock<Instant>>,
    ) {
        debug!(log, "Received packet"; "from" => %from, "contents" => from_utf8(packet).unwrap());
        Session::inc_expiration(expiration).await;
        if let Err(err) = sender.send(Packet::new(dest, packet.to_vec())).await {
            error!(log, "Error sending packet to channel"; "error" => %err);
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
    pub async fn send_to(&mut self, buf: &[u8]) -> Result<usize> {
        debug!(self.log, "Sending packet"; "dest" => self.dest, "contents" => from_utf8(buf).unwrap());
        return self.send.send_to(buf, &self.dest).await;
    }

    /// is_closed returns if the Session is closed or not.
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        return self.is_closed.load(Relaxed);
    }

    /// close closes this Session.
    pub fn close(&self) -> result::Result<(), watch::error::SendError<bool>> {
        debug!(self.log, "Session closed"; "from" => %self.from, "dest" => %self.dest);
        self.closer.broadcast(true)
    }
}

#[cfg(test)]
mod tests {
    use slog::info;
    use tokio::time;
    use tokio::time::delay_for;

    use crate::test_utils::{ephemeral_socket, logger, recv_udp};

    use super::*;

    #[tokio::test]
    async fn session_new() {
        time::pause();

        let log = logger();
        let mut socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();
        let (send_packet, mut recv_packet) = mpsc::channel::<Packet>(5);

        let mut sess = Session::new(&log, local_addr, local_addr, send_packet)
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
        let (sender, _) = mpsc::channel::<Packet>(1);
        let (local_addr, wait) = recv_udp().await;

        let mut session = Session::new(&log, local_addr, local_addr, sender)
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

        info!(log, ">> creating sessions");
        let sess = Session::new(&log, local_addr, local_addr, send_packet)
            .await
            .unwrap();
        info!(log, ">> session created and running");

        assert!(!sess.is_closed(), "session should not be closed");
        sess.close().unwrap();

        // Poll the state to wait for the change, because everything is async
        for _ in 1..10 {
            let is_closed = sess.is_closed();
            info!(log, "session closed?"; "closed" => is_closed);
            if is_closed {
                break;
            }

            delay_for(Duration::from_secs(1)).await;
        }

        assert!(sess.is_closed(), "session should be closed");
    }
}
