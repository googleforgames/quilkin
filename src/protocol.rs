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

use nom::bytes::complete;
use std::net::SocketAddr;
use tracing::Instrument;

use crate::utils::net;

// Magic number to distinguish control packets from regular traffic.
const MAGIC_NUMBER: &[u8] = b"QLKN";
const TIMESTAMP_LEN: usize = (i64::BITS / 8) as usize;
const VERSION: u8 = 0;
const VERSION_LEN: usize = 1;
const NONCE_LEN: usize = 1;
const LENGTH_LEN: usize = 2;
const DISCRIMINANT_LEN: usize = 1;

type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn spawn(port: u16) -> crate::Result<()> {
    let socket = net::DualStackLocalSocket::new(port)?;
    let v4_addr = socket.local_ipv4_addr()?;
    let v6_addr = socket.local_ip6_addr()?;
    tokio::spawn(
        async move {
            // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
            // packet, which is the maximum value of 16 a bit integer.
            let mut v4_buf = vec![0; 1 << 16];
            let mut v6_buf = vec![0; 1 << 16];
            let mut output_buf = Vec::new();

            loop {
                tracing::info!(%v4_addr, %v6_addr, "awaiting qcmp packets");

                match socket.recv_from(&mut v4_buf, &mut v6_buf).await {
                    Ok((size, source)) => {
                        let received_at = chrono::Utc::now().timestamp_nanos();
                        let contents = match source {
                            SocketAddr::V4(_) => &v4_buf[..size],
                            SocketAddr::V6(_) => &v6_buf[..size],
                        };

                        let command = match Protocol::parse(contents) {
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
                            .encode_into_buffer(&mut output_buf);

                        if let Err(error) = socket.send_to(&output_buf, &source).await {
                            tracing::warn!(%error, "error responding to ping");
                        }

                        output_buf.clear();
                    }
                    Err(error) => tracing::warn!(%error, "error receiving packet"),
                }
            }
        }
        .instrument(tracing::info_span!("qcmp_task", %v4_addr, %v6_addr)),
    );
    Ok(())
}

/// The set of possible QCMP commands.
#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    /// The initation of a ping command to send to a Quilkin proxy to measure
    /// latency.
    Ping {
        /// The timestamp from when the client sent the packet.
        client_timestamp: i64,
        /// The client's nonce.
        nonce: u8,
    },

    /// The reply from a Quilkin proxy from a [`Self::Ping`] command. Can be
    /// used with [`Protocol::round_trip_delay`] to measure latency between
    /// two machines.
    PingReply {
        /// The timestamp from when the client sent the ping packet.
        client_timestamp: i64,
        /// The client's nonce.
        nonce: u8,
        /// The timestamp from when the server received the ping packet.
        server_start_timestamp: i64,
        /// The timestamp from when the server sent the reply.
        server_transmit_timestamp: i64,
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
            client_timestamp: chrono::Utc::now().timestamp_nanos(),
        }
    }

    /// Creates a [`Self::PingReply`] from the client and server start timestamp.
    /// It's recommended to transmit as as soon as possible from creation to
    /// keep the start and transmit times as accurate as possible.
    pub fn ping_reply(nonce: u8, client_timestamp: i64, server_start_timestamp: i64) -> Self {
        Self::PingReply {
            nonce,
            client_timestamp,
            server_start_timestamp,
            server_transmit_timestamp: chrono::Utc::now().timestamp_nanos(),
        }
    }

    /// Encodes the protocol command into a buffer of bytes for network transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        self.encode_into_buffer(&mut buffer);
        buffer
    }

    /// Encodes the protocol command into a buffer of bytes for network transmission.
    pub fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend(MAGIC_NUMBER);
        buffer.push(VERSION);
        buffer.push(self.discriminant());
        buffer.extend_from_slice(&self.discriminant_length().to_be_bytes());

        let length = buffer.len();

        self.encode_payload(buffer);

        debug_assert_eq!(
            buffer.len(),
            length + usize::from(self.discriminant_length())
        );
    }

    /// Returns the packet's nonce.
    pub fn nonce(&self) -> u8 {
        match self {
            Protocol::Ping { nonce, .. } => *nonce,
            Protocol::PingReply { nonce, .. } => *nonce,
        }
    }

    fn encode_payload(&self, buffer: &mut Vec<u8>) {
        match self {
            Protocol::Ping {
                nonce,
                client_timestamp,
            } => {
                buffer.push(*nonce);
                buffer.extend_from_slice(&client_timestamp.to_be_bytes())
            }
            Protocol::PingReply {
                nonce,
                client_timestamp,
                server_start_timestamp,
                server_transmit_timestamp,
            } => {
                buffer.push(*nonce);
                buffer.extend_from_slice(&client_timestamp.to_be_bytes());
                buffer.extend_from_slice(&server_start_timestamp.to_be_bytes());
                buffer.extend_from_slice(&server_transmit_timestamp.to_be_bytes());
            }
        }
    }

    /// If the command is [`Protocol::PingReply`], with `client_response_timestamp`
    /// measures the roundtrip delay between the client machine, and the Quilkin
    /// proxy, using the same algorithm as [Network Time Protocol (NTP)][ntp].
    ///
    /// [ntp]: https://en.wikipedia.org/wiki/Network_Time_Protocol#Clock_synchronization_algorithm
    pub fn round_trip_delay(&self, client_response_timestamp: i64) -> Option<i64> {
        let Protocol::PingReply {
            client_timestamp,
            server_start_timestamp,
            server_transmit_timestamp,
            ..
        } = self
        else {
            return None;
        };

        Some(
            (client_response_timestamp - client_timestamp)
                - (server_transmit_timestamp - server_start_timestamp),
        )
    }

    /// Returns the discriminant code, identifying the payload.
    const fn discriminant(&self) -> u8 {
        match self {
            Self::Ping { .. } => 0,
            Self::PingReply { .. } => 1,
        }
    }

    /// Same as [`payload_length`] except for when the payload is already known.
    fn discriminant_length(&self) -> u16 {
        Self::payload_length(self.discriminant()).unwrap()
    }

    /// The expected length of payload based on its discriminant.
    const fn payload_length(discriminant: u8) -> Result<u16> {
        Ok(match discriminant {
            0 => NONCE_LEN as u16 + TIMESTAMP_LEN as u16,
            1 => NONCE_LEN as u16 + (TIMESTAMP_LEN as u16 * 3),
            code => return Err(Error::InvalidCommand(code)),
        })
    }

    /// Parses the provided input, and attempts to parse it as a `Protocol`
    /// packet. Returning `None` if the magic number is not present, and thus
    /// is not a QCMP packet, and returning `Err` when it was detected as a
    /// QCMP packet, but there was an error in parsing the payload.
    pub fn parse(input: &[u8]) -> Result<Option<Self>> {
        let Ok((input, _)) = complete::tag::<_, _, nom::error::Error<_>>(MAGIC_NUMBER)(input)
        else {
            return Ok(None);
        };

        let (input, version) = Self::parse_version(input)?;

        if version != 0 {
            return Err(Error::UnknownVersion(version));
        }

        let (input, discriminant) = Self::parse_discriminant(input)?;
        let (input, length) = Self::parse_length(input)?;
        let payload_length = Self::payload_length(discriminant)?;

        if usize::from(length) != input.len() {
            return Err(Error::LengthMismatch(length, input.len()));
        } else if length != payload_length {
            return Err(Error::LengthMismatch(length, payload_length.into()));
        }

        match discriminant {
            0 => Self::parse_ping_payload(input).map(Some),
            1 => Self::parse_ping_reply_payload(input).map(Some),
            _ => unreachable!(),
        }
    }

    fn parse_length(input: &[u8]) -> nom::IResult<&[u8], u16> {
        complete::take(LENGTH_LEN)(input)
            .map(|(input, length)| (input, u16::from_be_bytes([length[0], length[1]])))
    }

    fn parse_version(input: &[u8]) -> nom::IResult<&[u8], u8> {
        complete::take(VERSION_LEN)(input).map(|(input, version)| (input, version[0]))
    }

    fn parse_nonce(input: &[u8]) -> nom::IResult<&[u8], u8> {
        complete::take(NONCE_LEN)(input).map(|(input, nonce)| (input, nonce[0]))
    }

    fn parse_discriminant(input: &[u8]) -> nom::IResult<&[u8], u8> {
        complete::take(DISCRIMINANT_LEN)(input)
            .map(|(input, discriminant)| (input, discriminant[0]))
    }

    fn parse_timestamp(input: &[u8]) -> nom::IResult<&[u8], i64> {
        complete::take(TIMESTAMP_LEN)(input)
            .map(|(input, ts)| (input, i64::from_be_bytes(ts.try_into().unwrap())))
    }

    fn parse_ping_payload(input: &[u8]) -> Result<Self> {
        let (input, nonce) = Self::parse_nonce(input)?;
        let (_, client_timestamp) = Self::parse_timestamp(input)?;
        Ok(Self::Ping {
            nonce,
            client_timestamp,
        })
    }

    fn parse_ping_reply_payload(input: &[u8]) -> Result<Self> {
        let (input, nonce) = Self::parse_nonce(input)?;
        let (input, client_timestamp) = Self::parse_timestamp(input)?;
        let (input, server_start_timestamp) = Self::parse_timestamp(input)?;
        let (_, server_transmit_timestamp) = Self::parse_timestamp(input)?;
        Ok(Self::PingReply {
            nonce,
            client_timestamp,
            server_start_timestamp,
            server_transmit_timestamp,
        })
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
    #[error("failed to parse packet payload: {0}")]
    Parse(String),
}

impl From<nom::Err<nom::error::Error<&'_ [u8]>>> for Error {
    fn from(error: nom::Err<nom::error::Error<&'_ [u8]>>) -> Self {
        Self::Parse(error.to_string())
    }
}

#[cfg(test)]
mod tests {
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
            0,
            // Length
            0, 9,
            // Nonce
            0xBF,
            // Payload
            0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57,
        ];

        let ping = Protocol::parse(INPUT).unwrap().unwrap();

        assert!(matches!(ping, Protocol::Ping { nonce: 0xBF, .. }));

        assert_eq!(ping.encode(), INPUT);
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
            1,
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
            dbg!(ping_reply),
            Protocol::PingReply { nonce: 0xBF, .. }
        ));
        assert_eq!(ping_reply.encode(), INPUT);
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
            0,
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
        const INPUT: &[u8] = &[0xff, 0xff, 0, 0, 0, 0, 0x63, 0xb6, 0xe9, 0x57];

        assert!(Protocol::parse(INPUT).unwrap().is_none());
    }
}
