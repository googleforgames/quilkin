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
    pub async fn spawn(
        self,
        _shutdown: crate::ShutdownRx,
    ) -> eyre::Result<std::sync::mpsc::Receiver<()>> {
        let Self {
            worker_id,
            upstream_receiver,
            port,
            config,
            sessions,
            error_sender,
            buffer_pool,
        } = self;

        let (tx, rx) = std::sync::mpsc::channel();

        let thread_span =
            uring_span!(tracing::debug_span!("receiver", id = worker_id).or_current());

        let worker = uring_spawn!(thread_span, async move {
            crate::metrics::game_traffic_tasks().inc();
            let mut last_received_at = None;
            let socket = crate::net::DualStackLocalSocket::new(port)
                .unwrap()
                .make_refcnt();

            tracing::trace!(port, "bound worker");
            let send_socket = socket.clone();

            let inner_task = async move {
                let _ = tx.send(());

                loop {
                    tokio::select! {
                        result = upstream_receiver.recv() => {
                            match result {
                                Err(error) => {
                                    tracing::trace!(%error, "error receiving packet");
                                    crate::metrics::errors_total(
                                        crate::metrics::WRITE,
                                        &error.to_string(),
                                        &crate::metrics::EMPTY,
                                        )
                                        .inc();
                                }
                                Ok(crate::components::proxy::SendPacket {
                                    destination,
                                    asn_info,
                                    data,
                                }) => {
                                    let (result, _) = send_socket.send_to(data, destination).await;
                                    let asn_info = asn_info.as_ref().into();
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
                        }
                    }
                }
            };

            cfg_if::cfg_if! {
                if #[cfg(debug_assertions)] {
                    uring_inner_spawn!(inner_task.instrument(tracing::debug_span!("upstream").or_current()));
                } else {
                    uring_inner_spawn!(inner_task);
                }
            }

            let mut error_acc =
                crate::components::proxy::error::ErrorAccumulator::new(error_sender);
            let mut destinations = Vec::with_capacity(1);

            loop {
                // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
                // packet, which is the maximum value of 16 a bit integer.
                let buffer = buffer_pool.clone().alloc();

                let (result, contents) = socket.recv_from(buffer).await;
                let received_at = crate::time::UtcTimestamp::now();

                match result {
                    Ok((_size, mut source)) => {
                        source.set_ip(source.ip().to_canonical());
                        let packet = super::DownstreamPacket { contents, source };

                        if let Some(last_received_at) = last_received_at {
                            crate::metrics::packet_jitter(
                                crate::metrics::READ,
                                &crate::metrics::EMPTY,
                            )
                            .set((received_at - last_received_at).nanos());
                        }
                        last_received_at = Some(received_at);

                        Self::process_task(
                            packet,
                            worker_id,
                            &config,
                            &sessions,
                            &mut error_acc,
                            &mut destinations,
                        );
                    }
                    Err(error) => {
                        crate::metrics::game_traffic_task_closed().inc();
                        tracing::error!(%error, "error receiving packet");
                        return;
                    }
                }
            }
        });

        use eyre::WrapErr as _;
        worker.recv().context("failed to spawn receiver task")?;
        Ok(rx)
    }
}
