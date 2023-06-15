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

mod sessions;

use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::{
    endpoint::{Endpoint, EndpointAddress},
    filters::{Filter, ReadContext},
    protocol::Protocol,
    ttl_map::TryResult,
    Config,
};

pub use sessions::{Session, SessionArgs, SessionKey, SessionMap};

/// Packet received from local port
#[derive(Debug)]
struct DownstreamPacket {
    source: EndpointAddress,
    received_at: i64,
    contents: Vec<u8>,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub(crate) struct DownstreamReceiveWorkerConfig {
    /// ID of the worker.
    pub worker_id: usize,
    /// Socket with reused port from which the worker receives packets.
    pub socket: Arc<UdpSocket>,
    pub config: Arc<Config>,
    pub sessions: SessionMap,
}

impl DownstreamReceiveWorkerConfig {
    pub fn spawn(self) {
        let Self {
            worker_id,
            socket,
            config,
            sessions,
        } = self;

        tokio::spawn(async move {
            // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
            // packet, which is the maximum value of 16 a bit integer.
            let mut buf = vec![0; 1 << 16];
            loop {
                tracing::debug!(
                    id = worker_id,
                    addr = ?socket.local_addr(),
                    "Awaiting packet"
                );
                match socket.recv_from(&mut buf).await {
                    Ok((size, source)) => {
                        let packet = DownstreamPacket {
                            received_at: chrono::Utc::now().timestamp_nanos(),
                            source: source.into(),
                            contents: buf[..size].to_vec(),
                        };

                        Self::spawn_process_task(
                            packet, source, worker_id, &socket, &config, &sessions,
                        )
                    }
                    Err(error) => {
                        tracing::error!(%error, "error receiving packet");
                        return;
                    }
                }
            }
        });
    }

    #[inline]
    fn spawn_process_task(
        packet: DownstreamPacket,
        source: std::net::SocketAddr,
        worker_id: usize,
        socket: &Arc<UdpSocket>,
        config: &Arc<Config>,
        sessions: &SessionMap,
    ) {
        tracing::trace!(
            id = worker_id,
            size = packet.contents.len(),
            source = %source,
            contents=&*crate::utils::base64_encode(&packet.contents),
            "received packet from downstream"
        );

        tokio::spawn({
            let config = config.clone();
            let sessions = sessions.clone();
            let socket = socket.clone();

            async move {
                let timer = crate::metrics::processing_time(crate::metrics::READ).start_timer();

                match Self::process_downstream_received_packet(packet, config, socket, sessions)
                    .await
                {
                    Ok(size) => {
                        crate::metrics::packets_total(crate::metrics::READ).inc();
                        crate::metrics::bytes_total(crate::metrics::READ).inc_by(size as u64);
                    }
                    Err(error) => {
                        let source = error.to_string();
                        crate::metrics::errors_total(crate::metrics::READ, &source).inc();
                        crate::metrics::packets_dropped_total(crate::metrics::READ, &source).inc();
                    }
                }

                timer.stop_and_record();
            }
        });
    }

    /// Processes a packet by running it through the filter chain.
    async fn process_downstream_received_packet(
        packet: DownstreamPacket,
        config: Arc<Config>,
        downstream_socket: Arc<UdpSocket>,
        sessions: SessionMap,
    ) -> Result<usize, PipelineError> {
        if let Some(command) = Protocol::parse(&packet.contents)? {
            return Self::process_control_packet(packet, command, downstream_socket).await;
        }

        let endpoints: Vec<_> = config.clusters.value().endpoints().collect();
        if endpoints.is_empty() {
            return Err(PipelineError::NoUpstreamEndpoints);
        }

        let filters = config.filters.load();
        let mut context = ReadContext::new(endpoints, packet.source, packet.contents);
        filters.read(&mut context).await?;
        let mut bytes_written = 0;

        for endpoint in context.endpoints.iter() {
            bytes_written += Self::session_send_packet(
                &context.contents,
                &context.source,
                endpoint,
                &downstream_socket,
                &config,
                &sessions,
            )
            .await?;
        }

        Ok(bytes_written)
    }

    async fn process_control_packet(
        packet: DownstreamPacket,
        command: Protocol,
        downstream_socket: Arc<UdpSocket>,
    ) -> Result<usize, PipelineError> {
        match command {
            Protocol::Ping {
                client_timestamp,
                nonce,
            } => downstream_socket
                .send_to(
                    &Protocol::ping_reply(nonce, client_timestamp, packet.received_at).encode(),
                    packet.source.to_socket_addr().await?,
                )
                .await
                .map_err(From::from),
            Protocol::PingReply { .. } => {
                tracing::warn!("received unsupported ping reply");
                Ok(0)
            }
        }
    }

    /// Send a packet received from `recv_addr` to an endpoint.
    #[tracing::instrument(level="trace", skip_all, fields(source = %recv_addr, dest = %endpoint.address))]
    async fn session_send_packet(
        packet: &[u8],
        recv_addr: &EndpointAddress,
        endpoint: &Endpoint,
        downstream_socket: &Arc<UdpSocket>,
        config: &Arc<Config>,
        sessions: &SessionMap,
    ) -> Result<usize, PipelineError> {
        let session_key = SessionKey {
            source: recv_addr.clone(),
            dest: endpoint.address.clone(),
        };

        let send_future = match sessions.try_get(&session_key) {
            TryResult::Present(entry) => entry.send(packet),
            TryResult::Absent => {
                let session_args = SessionArgs {
                    config: config.clone(),
                    source: session_key.source.clone(),
                    downstream_socket: downstream_socket.clone(),
                    dest: endpoint.clone(),
                };

                let session = session_args.into_session().await?;
                let future = session.send(packet);
                sessions.insert(session_key, session);
                future
            }
            TryResult::Locked => {
                return Err(PipelineError::SessionMapLocked);
            }
        };

        send_future.await
    }
}

#[derive(thiserror::Error, Debug)]
pub enum PipelineError {
    #[error("No upstream endpoints available")]
    NoUpstreamEndpoints,
    #[error("session map was locked")]
    SessionMapLocked,
    #[error("filter {0}")]
    Filter(#[from] crate::filters::FilterError),
    #[error("qcmp: {0}")]
    Qcmp(#[from] crate::protocol::Error),
    #[error("OS level error: {0}")]
    Io(#[from] std::io::Error),
}
