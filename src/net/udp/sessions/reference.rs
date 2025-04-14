/*
 * Copyright 2024 Google LLC All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use crate::{components::proxy, net::PacketQueue};

impl super::SessionPool {
    pub(super) fn spawn_session(
        self: std::sync::Arc<Self>,
        raw_socket: socket2::Socket,
        port: u16,
        pending_sends: PacketQueue,
    ) -> Result<(), proxy::PipelineError> {
        let pool = self;

        uring_spawn!(
            uring_span!(tracing::debug_span!("session pool")),
            async move {
                let mut last_received_at = None;

                let socket =
                    std::sync::Arc::new(crate::net::DualStackLocalSocket::from_raw(raw_socket));
                let socket2 = socket.clone();
                let (tx, mut rx) = tokio::sync::oneshot::channel();

                uring_inner_spawn!(async move {
                    let (pending_sends, mut sends_rx) = pending_sends;
                    let mut sends_double_buffer = Vec::with_capacity(pending_sends.capacity());

                    while sends_rx.changed().await.is_ok() {
                        if !*sends_rx.borrow() {
                            tracing::trace!("io loop shutdown requested");
                            break;
                        }

                        sends_double_buffer = pending_sends.swap(sends_double_buffer);

                        for packet in sends_double_buffer.drain(..sends_double_buffer.len()) {
                            let destination = packet.destination.as_socket().unwrap();
                            tracing::trace!(
                                %destination,
                                length = packet.data.len(),
                                "sending packet upstream"
                            );
                            let (result, _) = socket2.send_to(packet.data, destination).await;
                            let asn_info = packet.asn_info.as_ref().into();
                            match result {
                                Ok(size) => {
                                    crate::metrics::packets_total(crate::metrics::READ, &asn_info)
                                        .inc();
                                    crate::metrics::bytes_total(crate::metrics::READ, &asn_info)
                                        .inc_by(size as u64);
                                }
                                Err(error) => {
                                    tracing::trace!(%error, "sending packet upstream failed");
                                    let source = error.to_string();
                                    crate::metrics::errors_total(
                                        crate::metrics::READ,
                                        &source,
                                        &asn_info,
                                    )
                                    .inc();
                                    crate::metrics::packets_dropped_total(
                                        crate::metrics::READ,
                                        &source,
                                        &asn_info,
                                    )
                                    .inc();
                                }
                            }
                        }
                    }

                    let _ = tx.send(());
                });

                loop {
                    let buf = pool.buffer_pool.clone().alloc();
                    tokio::select! {
                        received = socket.recv_from(buf) => {
                            let (result, buf) = received;
                            match result {
                                Err(error) => {
                                    tracing::trace!(%error, "error receiving packet");
                                    crate::metrics::errors_total(crate::metrics::WRITE, &error.to_string(), &crate::metrics::EMPTY).inc();
                                },
                                Ok((_size, recv_addr)) => pool.process_received_upstream_packet(buf, recv_addr, port, &mut last_received_at),
                            }
                        }
                        _ = &mut rx => {
                            tracing::debug!("Closing upstream socket loop, downstream closed");
                            return;
                        }
                    }
                }
            }
        );

        Ok(())
    }
}
