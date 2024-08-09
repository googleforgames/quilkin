/*
 * Copyright 2023 Google LLC
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

//! Logic for parsing and generating Quilkin Control Message Protocol (QCMP) messages.

use crate::{
    net::{
        phoenix::{DistanceMeasure, Measurement},
        DualStackEpollSocket, DualStackLocalSocket,
    },
    time::{DurationNanos, UtcTimestamp},
};
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;

// Magic number to distinguish control packets from regular traffic.
const MAGIC_NUMBER: &[u8] = b"QLKN";
const VERSION: u8 = 0;
/// The minimum length of a QCMP packet
pub const MIN_QCMP_PACKET_LEN: usize = 4 /* MAGIC_NUMBER */ + 1 /* VERSION */ + 1 /* DISCRIMINANT */ + 1 /* NONCE */ + 2 /* LENGTH */ + std::mem::size_of::<u64>();
/// The maximum length of a QCMP packet, including 2 additional i64 timestamps
pub const MAX_QCMP_PACKET_LEN: usize = MIN_QCMP_PACKET_LEN + std::mem::size_of::<u64>() * 2;
const PING: u8 = 0;
const PONG: u8 = 1;

pub struct QcmpPacket {
    buf: [u8; MAX_QCMP_PACKET_LEN],
    len: usize,
}

impl Default for QcmpPacket {
    fn default() -> Self {
        Self {
            buf: [0; MAX_QCMP_PACKET_LEN],
            len: 0,
        }
    }
}

impl std::ops::Deref for QcmpPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[..self.len]
    }
}

type Result<T, E = Error> = std::result::Result<T, E>;

struct PacketBuilder<'buf> {
    packet: &'buf mut QcmpPacket,
    offset: usize,
}

impl<'buf> PacketBuilder<'buf> {
    #[inline]
    fn wrap(packet: &'buf mut QcmpPacket) -> Self {
        packet.len = 0;
        Self { packet, offset: 0 }
    }

    #[inline]
    fn push(&mut self, val: u8) {
        self.packet.buf[self.offset] = val;
        self.offset += 1;
    }

    #[inline]
    fn push_slice(&mut self, slice: &[u8]) {
        self.packet.buf[self.offset..self.offset + slice.len()].copy_from_slice(slice);
        self.offset += slice.len();
    }

    #[inline]
    fn finalize(self) -> &'buf [u8] {
        self.packet.buf[self.offset..].fill(0);
        self.packet.len = self.offset;
        &self.packet.buf[..self.offset]
    }
}

struct PacketParser<'buf> {
    packet: &'buf [u8],
    offset: usize,
}

impl<'buf> PacketParser<'buf> {
    fn wrap(packet: &'buf [u8]) -> Result<Self> {
        if packet.len() < MIN_QCMP_PACKET_LEN {
            return Err(Error::LengthMismatch(
                MIN_QCMP_PACKET_LEN as _,
                packet.len(),
            ));
        }

        Ok(Self { packet, offset: 0 })
    }

    #[inline]
    fn read(&mut self) -> u8 {
        let index = self.offset;
        self.offset += 1;
        // SAFETY: We manually check the packet size before any reads
        unsafe { *self.packet.get_unchecked(index) }
    }

    #[inline]
    fn read_slice<const N: usize>(&mut self) -> [u8; N] {
        let mut s = [0u8; N];
        // SAFETY: We manually check the packet size before any reads
        s.copy_from_slice(unsafe { self.packet.get_unchecked(self.offset..self.offset + N) });
        self.offset += N;
        s
    }
}

/// A measurement implementation using QCMP pings for measuring the distance
/// between nodes.
#[derive(Debug, Clone)]
pub struct QcmpMeasurement {
    socket: Arc<DualStackEpollSocket>,
    #[cfg(test)]
    delay: Option<Duration>,
}

impl QcmpMeasurement {
    pub fn new() -> crate::Result<Self> {
        Ok(Self {
            socket: Arc::new(DualStackEpollSocket::new(0)?),
            #[cfg(test)]
            delay: None,
        })
    }

    #[cfg(test)]
    pub fn with_artificial_delay(delay: Duration) -> crate::Result<Self> {
        Ok(Self {
            socket: Arc::new(DualStackEpollSocket::new(0)?),
            delay: Some(delay),
        })
    }
}

#[async_trait::async_trait]
impl Measurement for QcmpMeasurement {
    async fn measure_distance(
        &self,
        address: std::net::SocketAddr,
    ) -> eyre::Result<DistanceMeasure> {
        {
            let mut ping = QcmpPacket::default();
            self.socket
                .send_to(Protocol::ping().encode(&mut ping), address)
                .await?;
        }

        let mut recv = [0u8; 512];

        let (size, _) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            self.socket.recv_from(&mut recv),
        )
        .await??;

        #[cfg(test)]
        if let Some(ad) = self.delay {
            tokio::time::sleep(ad).await;
        }

        let now = UtcTimestamp::now();
        let Some(reply) = Protocol::parse(&recv[..size])? else {
            return Err(eyre::eyre!("received non qcmp packet {:?}", &recv[..size]));
        };

        reply
            .distance(now)
            .ok_or_else(|| eyre::eyre!("received non ping reply"))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn spawn(socket: socket2::Socket, mut shutdown_rx: crate::ShutdownRx) -> crate::Result<()> {
    let port = crate::net::socket_port(&socket);

    uring_spawn!(uring_span!(tracing::debug_span!("qcmp")), async move {
        let mut input_buf = vec![0; 1 << 16];
        let socket = DualStackLocalSocket::new(port).unwrap();
        let mut output_buf = QcmpPacket::default();

        loop {
            let result = tokio::select! {
                result = socket.recv_from(input_buf) => result,
                _ = shutdown_rx.changed() => return,
            };
            match result {
                (Ok((size, source)), new_input_buf) => {
                    input_buf = new_input_buf;
                    let received_at = UtcTimestamp::now();
                    let command = match Protocol::parse(&input_buf[..size]) {
                        Ok(Some(command)) => command,
                        Ok(None) => {
                            tracing::debug!("rejected non-qcmp packet");
                            continue;
                        }
                        Err(error) => {
                            tracing::debug!(%error, "rejected malformed packet");
                            continue;
                        }
                    };

                    let Protocol::Ping {
                        client_timestamp,
                        nonce,
                    } = command
                    else {
                        tracing::warn!("rejected unsupported QCMP packet");
                        continue;
                    };

                    Protocol::ping_reply(nonce, client_timestamp, received_at)
                        .encode(&mut output_buf);

                    tracing::debug!("sending ping reply {:?}", &output_buf.buf[..output_buf.len]);

                    output_buf = match socket.send_to(output_buf, source).await {
                        (Ok(_), buf) => buf,
                        (Err(error), buf) => {
                            tracing::warn!(%error, "error responding to ping");
                            buf
                        }
                    };
                }
                (Err(error), new_input_buf) => {
                    tracing::warn!(%error, "error receiving packet");
                    input_buf = new_input_buf
                }
            };
        }
    });

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn spawn(socket: socket2::Socket, mut shutdown_rx: crate::ShutdownRx) -> crate::Result<()> {
    use crate::components::proxy::io_uring_shared::EventFd;
    use eyre::Context as _;

    let port = crate::net::socket_port(&socket);

    // Create an eventfd so we can signal to the qcmp loop when we want to exit
    let mut shutdown_event = EventFd::new()?;
    let shutdown = shutdown_event.writer();

    // Spawn a task on the main loop whose sole purpose is to signal the eventfd
    tokio::task::spawn(async move {
        let _ = shutdown_rx.changed().await;
        shutdown.write(1);
    });

    let _thread_span = uring_span!(tracing::debug_span!("qcmp").or_current());
    let dispatcher = tracing::dispatcher::get_default(|d| d.clone());

    std::thread::Builder::new()
        .name("qcmp".into())
        .spawn(move || -> eyre::Result<()> {
            let _guard = tracing::dispatcher::set_default(&dispatcher);

            let mut ring = io_uring::IoUring::new(3).context("unable to create io uring")?;
            let (submitter, mut sq, mut cq) = ring.split();

            const RECV: u64 = 0;
            const SEND: u64 = 1;
            const SHUTDOWN: u64 = 2;

            // Queue the read from the shutdown eventfd used to signal when the loop
            // should exit
            let entry = shutdown_event.io_uring_entry().user_data(SHUTDOWN);
            // SAFETY: the memory being written to is located on the stack inside the shutdown event, and is alive
            // at least as long as the uring loop
            unsafe {
                sq.push(&entry).context("unable to insert io-uring entry")?;
            }

            // Our loop is simple and only ever processes one ping/pong pair at a time
            // so we just reuse the same buffer for both receives and sends
            let mut buf = QcmpPacket::default();
            // SAFETY: msghdr is POD
            let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
            // SAFETY: msghdr is POD
            let addr = unsafe {
                socket2::SockAddr::new(
                    std::mem::zeroed(),
                    std::mem::size_of::<libc::sockaddr_storage>() as _,
                )
            };

            let mut iov = libc::iovec {
                iov_base: buf.buf.as_mut_ptr() as *mut _,
                iov_len: 0,
            };

            msghdr.msg_iov = std::ptr::addr_of_mut!(iov);
            msghdr.msg_iovlen = 1;
            msghdr.msg_name = addr.as_ptr() as *mut libc::sockaddr_storage as *mut _;
            msghdr.msg_namelen = addr.len();

            let msghdr_mut = std::ptr::addr_of_mut!(msghdr);

            let socket = DualStackLocalSocket::new(port)
                .context("failed to create already bound qcmp socket")?;
            let socket_fd = socket.raw_fd();

            let enqueue_recv =
                |sq: &mut io_uring::SubmissionQueue, iov: &mut libc::iovec| -> eyre::Result<()> {
                    iov.iov_len = MAX_QCMP_PACKET_LEN;
                    let entry = io_uring::opcode::RecvMsg::new(socket_fd, msghdr_mut)
                        .build()
                        .user_data(RECV);
                    // SAFETY: the memory being written to is located on the stack and outlives the uring loop
                    unsafe { sq.push(&entry) }.context("unable to insert io-uring entry")?;
                    Ok(())
                };

            enqueue_recv(&mut sq, &mut iov)?;

            sq.sync();

            loop {
                match submitter.submit_and_wait(1) {
                    Ok(_) => {}
                    Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => {}
                    Err(err) => {
                        return Err(err).context("failed to submit io-uring operations");
                    }
                }
                cq.sync();

                let mut has_pending_send = false;
                for cqe in &mut cq {
                    let ret = cqe.result();

                    match cqe.user_data() {
                        RECV => {
                            if ret < 0 {
                                let error = std::io::Error::from_raw_os_error(-ret).to_string();
                                tracing::error!(%error, "failed to send QCMP response");
                                continue;
                            }

                            buf.len = ret as _;
                            let received_at = UtcTimestamp::now();
                            let command = match Protocol::parse(&buf) {
                                Ok(Some(command)) => command,
                                Ok(None) => {
                                    tracing::debug!("rejected non-QCMP packet");
                                    continue;
                                }
                                Err(error) => {
                                    tracing::debug!(%error, "rejected malformed packet");
                                    continue;
                                }
                            };

                            let Protocol::Ping {
                                client_timestamp,
                                nonce,
                            } = command
                            else {
                                tracing::warn!("rejected unsupported QCMP packet");
                                continue;
                            };

                            Protocol::ping_reply(nonce, client_timestamp, received_at)
                                .encode(&mut buf);

                            tracing::debug!("sending QCMP ping reply");

                            // Update the iovec with the actual length of the pong
                            iov.iov_len = buf.len;

                            // Note we don't have to do anything else with the msghdr
                            // as the recv has already filled in the socket address
                            // of the sender, which is also our destination

                            {
                                let entry = io_uring::opcode::SendMsg::new(
                                    socket_fd,
                                    std::ptr::addr_of!(msghdr),
                                )
                                .build()
                                .user_data(SEND);
                                // SAFETY: the memory being read from is located on the stack and outlives the uring loop
                                if unsafe { sq.push(&entry) }.is_err() {
                                    tracing::error!("failed to enqueue QCMP pong response");
                                    continue;
                                }
                            }

                            has_pending_send = true;
                        }
                        SEND => {
                            if ret < 0 {
                                let error = std::io::Error::from_raw_os_error(-ret).to_string();
                                tracing::error!(%error, "failed to send QCMP response");
                            }
                        }
                        SHUTDOWN => {
                            tracing::info!("QCMP thread was signaled to shutdown");
                            return Ok(());
                        }
                        ud => unreachable!("io-uring user data {ud} is invalid"),
                    }
                }

                if !has_pending_send {
                    enqueue_recv(&mut sq, &mut iov)?;
                }

                sq.sync();
            }
        })?;

    Ok(())
}

/// The set of possible QCMP commands.
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    /// The initation of a ping command to send to a Quilkin proxy to measure
    /// latency.
    Ping {
        /// The timestamp from when the client sent the packet.
        client_timestamp: UtcTimestamp,
        /// The client's nonce.
        nonce: u8,
    },

    /// The reply from a Quilkin proxy from a [`Self::Ping`] command. Can be
    /// used with [`Protocol::round_trip_delay`] to measure latency between
    /// two machines.
    PingReply {
        /// The timestamp from when the client sent the ping packet.
        client_timestamp: UtcTimestamp,
        /// The client's nonce.
        nonce: u8,
        /// The timestamp from when the server received the ping packet.
        server_start_timestamp: UtcTimestamp,
        /// The timestamp from when the server sent the reply.
        server_transmit_timestamp: UtcTimestamp,
    },
}

impl Protocol {
    /// Creates a [`Self::Ping`] with a random nonce, should be sent
    /// as soon as possible from creation to maintain accuracy.
    pub fn ping() -> Self {
        Self::ping_with_nonce(rand::random())
    }

    /// Creates a [`Self::Ping`] with a user-specified nonce, should be sent
    /// as soon as possible from creation to maintain accuracy.
    pub fn ping_with_nonce(nonce: u8) -> Self {
        Self::Ping {
            nonce,
            client_timestamp: UtcTimestamp::now(),
        }
    }

    /// Creates a [`Self::PingReply`] from the client and server start timestamp.
    /// It's recommended to transmit as as soon as possible from creation to
    /// keep the start and transmit times as accurate as possible.
    pub fn ping_reply(
        nonce: u8,
        client_timestamp: UtcTimestamp,
        server_start_timestamp: UtcTimestamp,
    ) -> Self {
        Self::PingReply {
            nonce,
            client_timestamp,
            server_start_timestamp,
            server_transmit_timestamp: UtcTimestamp::now(),
        }
    }

    /// Encodes the protocol command into a buffer of bytes for network transmission.
    pub fn encode<'buf>(&self, buffer: &'buf mut QcmpPacket) -> &'buf [u8] {
        let mut pb = PacketBuilder::wrap(buffer);
        pb.push_slice(MAGIC_NUMBER);
        pb.push(VERSION);
        pb.push(self.discriminant());
        pb.push_slice(&self.discriminant_length().to_be_bytes());

        #[cfg(debug_assertions)]
        {
            let length = pb.offset;
            self.encode_payload(&mut pb);

            assert_eq!(pb.offset, length + usize::from(self.discriminant_length()));
        }

        #[cfg(not(debug_assertions))]
        {
            self.encode_payload(&mut pb);
        }

        pb.finalize()
    }

    /// Returns the packet's nonce.
    pub fn nonce(&self) -> u8 {
        match self {
            Protocol::Ping { nonce, .. } => *nonce,
            Protocol::PingReply { nonce, .. } => *nonce,
        }
    }

    fn encode_payload(&self, pb: &mut PacketBuilder<'_>) {
        pb.push(self.nonce());

        let mut ets = |ts: &UtcTimestamp| {
            pb.push_slice(&ts.unix_nanos().to_be_bytes());
        };

        match self {
            Protocol::Ping {
                client_timestamp, ..
            } => {
                ets(client_timestamp);
            }
            Protocol::PingReply {
                client_timestamp,
                server_start_timestamp,
                server_transmit_timestamp,
                ..
            } => {
                ets(client_timestamp);
                ets(server_start_timestamp);
                ets(server_transmit_timestamp);
            }
        }
    }

    /// If the command is [`Protocol::PingReply`], with `client_response_timestamp`
    /// measures the roundtrip delay between the client machine, and the Quilkin
    /// proxy, using the same algorithm as [Network Time Protocol (NTP)][ntp].
    ///
    /// [ntp]: https://en.wikipedia.org/wiki/Network_Time_Protocol#Clock_synchronization_algorithm
    pub fn round_trip_delay(
        &self,
        client_response_timestamp: UtcTimestamp,
    ) -> Option<DurationNanos> {
        let Protocol::PingReply {
            client_timestamp,
            server_start_timestamp,
            server_transmit_timestamp,
            ..
        } = self
        else {
            return None;
        };

        Some(DurationNanos::from_nanos(
            (client_response_timestamp.unix_nanos() - client_timestamp.unix_nanos())
                - (server_transmit_timestamp.unix_nanos() - server_start_timestamp.unix_nanos()),
        ))
    }

    /// If the command is [`Protocol::PingReply`], with `client_response_timestamp`
    /// returns the time between the client -> server, and the server -> client.
    pub fn distance(&self, client_response_timestamp: UtcTimestamp) -> Option<DistanceMeasure> {
        let Protocol::PingReply {
            client_timestamp,
            server_start_timestamp,
            server_transmit_timestamp,
            ..
        } = self
        else {
            return None;
        };

        Some(DistanceMeasure {
            incoming: *server_start_timestamp - *client_timestamp,
            outgoing: client_response_timestamp - *server_transmit_timestamp,
        })
    }

    /// Returns the discriminant code, identifying the payload.
    const fn discriminant(&self) -> u8 {
        match self {
            Self::Ping { .. } => PING,
            Self::PingReply { .. } => PONG,
        }
    }

    /// Same as [`payload_length`] except for when the payload is already known.
    fn discriminant_length(&self) -> u16 {
        Self::payload_length(self.discriminant()).unwrap()
    }

    /// The expected length of payload based on its discriminant.
    const fn payload_length(discriminant: u8) -> Result<u16> {
        let num = match discriminant {
            PING => 1,
            PONG => 3,
            code => return Err(Error::InvalidCommand(code)),
        };

        Ok(1 + std::mem::size_of::<i64>() as u16 * num)
    }

    /// Parses the provided input, and attempts to parse it as a `Protocol`
    /// packet.
    ///
    /// Returns `None` if the magic number is not present, and thus is not a
    /// QCMP packet, and returning `Err` when it was detected as a QCMP packet,
    /// but there was an error in parsing the payload.
    pub fn parse(input: &[u8]) -> Result<Option<Self>> {
        let mut pp = PacketParser::wrap(input)?;

        let magic = pp.read_slice::<4>();
        if magic != MAGIC_NUMBER {
            return Ok(None);
        }

        let version = pp.read();
        if version != VERSION {
            return Err(Error::UnknownVersion(version));
        }

        let discriminant = pp.read();
        // Now that we know the packet kind we can ensure the rest of the expected
        // packet length is available to avoid panics
        let size = match discriminant {
            PING => MIN_QCMP_PACKET_LEN,
            PONG => MAX_QCMP_PACKET_LEN,
            unknown => return Err(Error::InvalidCommand(unknown)),
        };

        if pp.packet.len() < size {
            return Err(Error::LengthMismatch(size as _, pp.packet.len()));
        }

        let length = u16::from_be_bytes(pp.read_slice::<2>());
        let payload_length = Self::payload_length(discriminant)?;

        if length != payload_length {
            return Err(Error::LengthMismatch(length, payload_length.into()));
        }

        let remainder = pp.packet.len() - pp.offset;

        if usize::from(length) != remainder {
            return Err(Error::LengthMismatch(length, remainder));
        }

        let nonce = pp.read();

        fn parse_timestamp(pp: &mut PacketParser<'_>) -> UtcTimestamp {
            UtcTimestamp::from_nanos(i64::from_be_bytes(pp.read_slice::<8>()))
        }

        let payload = match discriminant {
            PING => Self::Ping {
                nonce,
                client_timestamp: parse_timestamp(&mut pp),
            },
            PONG => {
                let client_timestamp = parse_timestamp(&mut pp);
                let server_start_timestamp = parse_timestamp(&mut pp);
                let server_transmit_timestamp = parse_timestamp(&mut pp);
                Self::PingReply {
                    nonce,
                    client_timestamp,
                    server_start_timestamp,
                    server_transmit_timestamp,
                }
            }
            _ => unreachable!("we should have already verified the discriminant"),
        };

        Ok(Some(payload))
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("unknown version: {0}")]
    UnknownVersion(u8),
    #[error(
        "available input does not match specified packet length. specified: {0}, available: {1}"
    )]
    LengthMismatch(u16, usize),
    #[error("unknown command code: {0}")]
    InvalidCommand(u8),
}

#[cfg(test)]
mod tests {
    use crate::net::raw_socket_with_reuse;

    use super::*;

    #[test]
    fn ping() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // Magic
            b'Q', b'L', b'K', b'N',
            // Version
            0,
            // Code
            PING,
            // Length
            0, 9,
            // Nonce
            0xBF,
            // Payload
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
        ];

        let ping = Protocol::parse(INPUT).unwrap().unwrap();

        assert!(matches!(ping, Protocol::Ping { nonce: 0xBF, .. }));

        let mut packet = QcmpPacket::default();
        assert_eq!(ping.encode(&mut packet), INPUT);
    }

    #[test]
    fn ping_reply() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // Magic
            b'Q', b'L', b'K', b'N',
            // Version
            0,
            // Code
            PONG,
            // Length
            0, 25,
            // Nonce
            0xBF,
            // Payload
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
        ];

        let ping_reply = Protocol::parse(INPUT).unwrap().unwrap();

        assert!(matches!(
            ping_reply,
            Protocol::PingReply { nonce: 0xBF, .. }
        ));
        let mut packet = QcmpPacket::default();
        assert_eq!(ping_reply.encode(&mut packet), INPUT);
    }

    #[test]
    fn reject_malformed_packet() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // Magic
            b'Q', b'L', b'K', b'N',
            // Version
            0,
            // Code (intentionally Ping)
            PING,
            // Length
            0, 25,
            // Nonce
            0xBF,
            // Payload
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
        ];

        Protocol::parse(INPUT).unwrap_err();
    }

    #[test]
    fn reject_unknown_packet() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // Magic
            b'Q', b'L', b'K', b'N',
            // Version
            0,
            // Code
            0xff,
        ];

        Protocol::parse(INPUT).unwrap_err();
    }

    #[test]
    fn reject_unknown_version() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // Magic
            b'Q', b'L', b'K', b'N',
            // Version
            0xff,
        ];

        Protocol::parse(INPUT).unwrap_err();
    }

    #[test]
    fn reject_no_magic_header() {
        #[rustfmt::skip]
        const INPUT: &[u8] = &[
            // Magic
            b'Q', 0xff, b'K', b'N',
            // Version
            0,
            // Code
            PING,
            // Length
            0, 9,
            // Nonce
            0xBF,
            // Payload
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
        ];

        assert!(Protocol::parse(INPUT).unwrap().is_none());
    }

    #[tokio::test]
    async fn qcmp_measurement() {
        let socket = raw_socket_with_reuse(0).unwrap();
        let addr = socket.local_addr().unwrap().as_socket().unwrap();

        let (_tx, rx) = crate::make_shutdown_channel(Default::default());
        spawn(socket, rx).unwrap();

        let delay = Duration::from_millis(50);
        let node = QcmpMeasurement::with_artificial_delay(delay).unwrap();

        // fire messages until we get one back, so we know the socket is ready.
        let mut check = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if node.measure_distance(addr).await.is_ok() {
                check = true;
                break;
            }
        }
        assert!(check, "timed out on initial qcmp spawn");

        for _ in 0..3 {
            let dm = node.measure_distance(addr).await.unwrap();
            let total = dm.total();

            assert!(
                total > delay && total < delay * 2,
                "Node1's distance is {total:?}, expected > {delay:?} and less than {:?}",
                delay * 2
            );
        }
    }
}
