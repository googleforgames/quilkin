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
    Config,
};

pub use sessions::{Session, SessionKey, SessionMap};

/// Packet received from local port
#[derive(Debug)]
struct DownstreamPacket {
    asn_info: Option<crate::maxmind_db::IpNetEntry>,
    contents: Vec<u8>,
    received_at: i64,
    source: std::net::SocketAddr,
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
            let mut last_received_at = None;
            loop {
                tracing::debug!(
                    id = worker_id,
                    addr = ?socket.local_addr(),
                    "Awaiting packet"
                );

                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((size, source)) => {
                                let packet = DownstreamPacket {
                                    received_at: chrono::Utc::now().timestamp_nanos(),
                                    asn_info: crate::maxmind_db::MaxmindDb::lookup(source.ip()),
                                    contents: buf[..size].to_vec(),
                                    source,
                                };

                                if let Some(last_received_at) = last_received_at {
                                    crate::metrics::packet_jitter(
                                        crate::metrics::READ,
                                        packet.asn_info.as_ref(),
                                    )
                                        .set(packet.received_at - last_received_at);
                                }
                                last_received_at = Some(packet.received_at);

                                Self::spawn_process_task(packet, source, worker_id, &socket, &config, &sessions)
                            }
                            Err(error) => {
                                tracing::error!(%error, "error receiving packet");
                                return;
                            }
                        }
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

                let asn_info = packet.asn_info.clone();
                let asn_info = asn_info.as_ref();
                match Self::process_downstream_received_packet(packet, config, socket, sessions)
                    .await
                {
                    Ok(size) => {
                        crate::metrics::packets_total(crate::metrics::READ, asn_info).inc();
                        crate::metrics::bytes_total(crate::metrics::READ, asn_info)
                            .inc_by(size as u64);
                    }
                    Err(error) => {
                        let source = error.to_string();
                        crate::metrics::errors_total(crate::metrics::READ, &source, asn_info).inc();
                        crate::metrics::packets_dropped_total(
                            crate::metrics::READ,
                            &source,
                            asn_info,
                        )
                        .inc();
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
        let endpoints: Vec<_> = config.clusters.read().endpoints().collect();
        if endpoints.is_empty() {
            return Err(PipelineError::NoUpstreamEndpoints);
        }

        let filters = config.filters.load();
        let mut context = ReadContext::new(endpoints, packet.source.into(), packet.contents);
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
                packet.asn_info.clone(),
            )
            .await?;
        }

        Ok(bytes_written)
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
        asn_info: Option<crate::maxmind_db::IpNetEntry>,
    ) -> Result<usize, PipelineError> {
        let session_key = SessionKey {
            source: recv_addr.clone(),
            dest: endpoint.address.clone(),
        };

        let send_future = match sessions.get(&session_key) {
            Some(entry) => entry.send(packet),
            None => {
                let session = Session::new(
                    config.clone(),
                    session_key.source.clone(),
                    downstream_socket.clone(),
                    endpoint.clone(),
                    asn_info,
                )?;

                let future = session.send(packet);
                sessions.insert(session_key, session);
                future
            }
        };

        send_future.await
    }
}

#[derive(thiserror::Error, Debug)]
pub enum PipelineError {
    #[error("No upstream endpoints available")]
    NoUpstreamEndpoints,
    #[error("filter {0}")]
    Filter(#[from] crate::filters::FilterError),
    #[error("qcmp: {0}")]
    Qcmp(#[from] crate::protocol::Error),
    #[error("OS level error: {0}")]
    Io(#[from] std::io::Error),
}
