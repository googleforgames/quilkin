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

//! The reference implementation is used for non-Linux targets

impl super::DownstreamReceiveWorkerConfig {
    pub fn spawn(self, packet_queue: crate::net::PacketQueue) -> eyre::Result<()> {
        let Self {
            worker_id,
            port,
            config,
            sessions,
            buffer_pool,
        } = self;

        let thread_span =
            uring_span!(tracing::debug_span!("receiver", id = worker_id).or_current());
        let (tx, mut rx) = tokio::sync::oneshot::channel();

        let worker = uring_spawn!(thread_span, async move {
            crate::metrics::game_traffic_tasks().inc();
            let mut last_received_at = None;
            let socket = crate::net::DualStackLocalSocket::new(port)
                .unwrap()
                .make_refcnt();

            tracing::trace!(port, "bound worker");
            let send_socket = socket.clone();

            let inner_task = async move {
                let (packet_queue, mut sends_rx) = packet_queue;
                let mut sends_double_buffer = Vec::with_capacity(packet_queue.capacity());

                while sends_rx.changed().await.is_ok() {
                    if !*sends_rx.borrow() {
                        tracing::trace!("io loop shutdown requested");
                        break;
                    }

                    sends_double_buffer = packet_queue.swap(sends_double_buffer);

                    for packet in sends_double_buffer.drain(..sends_double_buffer.len()) {
                        let (result, _) = send_socket
                            .send_to(packet.data, packet.destination.as_socket().unwrap())
                            .await;
                        let asn_info = packet.asn_info.as_ref().into();
                        match result {
                            Ok(size) => {
                                crate::metrics::packets_total(crate::metrics::WRITE, &asn_info)
                                    .inc();
                                crate::metrics::bytes_total(crate::metrics::WRITE, &asn_info)
                                    .inc_by(size as u64);
                            }
                            Err(error) => {
                                let source = error.to_string();
                                crate::metrics::errors_total(
                                    crate::metrics::WRITE,
                                    &source,
                                    &asn_info,
                                )
                                .inc();
                                crate::metrics::packets_dropped_total(
                                    crate::metrics::WRITE,
                                    &source,
                                    &asn_info,
                                )
                                .inc();
                            }
                        }
                    }
                }

                let _ = tx.send(());
            };

            cfg_if::cfg_if! {
                if #[cfg(debug_assertions)] {
                    uring_inner_spawn!(inner_task.instrument(tracing::debug_span!("upstream").or_current()));
                } else {
                    uring_inner_spawn!(inner_task);
                }
            }

            let mut destinations = Vec::with_capacity(1);

            loop {
                // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
                // packet, which is the maximum value of 16 a bit integer.
                let buffer = buffer_pool.clone().alloc();

                tokio::select! {
                    received = socket.recv_from(buffer) => {
                        let received_at = crate::time::UtcTimestamp::now();
                        let (result, buffer) = received;

                        match result {
                            Ok((_size, mut source)) => {
                                source.set_ip(source.ip().to_canonical());
                                let packet = super::DownstreamPacket { contents: buffer, source };

                                if let Some(last_received_at) = last_received_at {
                                    crate::metrics::packet_jitter(
                                        crate::metrics::READ,
                                        &crate::metrics::EMPTY,
                                    )
                                    .set((received_at - last_received_at).nanos());
                                }
                                last_received_at = Some(received_at);

                                packet.process(
                                    worker_id,
                                    &config,
                                    &sessions,
                                    &mut destinations,
                                );
                            }
                            Err(error) => {
                                tracing::error!(%error, "error receiving packet");
                                return;
                            }
                        }
                    }
                    _ = &mut rx => {
                        crate::metrics::game_traffic_task_closed().inc();
                        tracing::debug!("Closing downstream socket loop, shutdown requested");
                        return;
                    }
                }
            }
        });

        use eyre::WrapErr as _;
        worker.recv().context("failed to spawn receiver task")?;
        Ok(())
    }
}
