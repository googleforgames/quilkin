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

pub type Notifier = tokio::sync::watch::Sender<bool>;
pub type Receiver = tokio::sync::watch::Receiver<bool>;
pub use tokio::net::UdpSocket as Socket;

pub const NAME: &str = "tokio::net";

#[track_caller]
pub fn from_system_socket(socket: super::SystemSocket) -> Socket {
    Socket::from_std(std::net::UdpSocket::from(socket.into_inner())).unwrap()
}

#[track_caller]
pub fn queue() -> (super::Notifier, super::Receiver) {
    let (tx, rx) = tokio::sync::watch::channel(true);

    (super::Notifier::Polling(tx), super::Receiver::Polling(rx))
}

pub fn listen(
    super::Listener {
        worker_id,
        port,
        config,
        sessions,
        buffer_pool,
    }: super::Listener,
    packet_queue: crate::net::packet::PacketQueue,
) -> eyre::Result<()> {
    let thread_span = uring_span!(tracing::debug_span!("receiver", id = worker_id).or_current());
    let (tx, mut rx) = tokio::sync::oneshot::channel();

    let worker = uring_spawn!(thread_span, async move {
        crate::metrics::game_traffic_tasks().inc();
        let mut last_received_at = None;
        let socket = std::sync::Arc::new(crate::net::Socket::polling_from_port(port).unwrap());

        tracing::trace!(port, "bound worker");
        let send_socket = socket.clone();

        let inner_task = async move {
            let (packet_queue, mut sends_rx) = packet_queue;
            let mut sends_double_buffer = Vec::with_capacity(packet_queue.capacity());

            while sends_rx.as_polling_mut().changed().await.is_ok() {
                if !*sends_rx.as_polling().borrow() {
                    tracing::trace!("io loop shutdown requested");
                    break;
                }

                sends_double_buffer = packet_queue.swap(sends_double_buffer);

                for packet in sends_double_buffer.drain(..sends_double_buffer.len()) {
                    let result = send_socket
                        .send_to(packet.data, packet.destination.as_socket().unwrap())
                        .await;
                    let asn_info = packet.asn_info.as_ref().into();
                    match result {
                        Ok(size) => {
                            crate::metrics::packets_total(crate::metrics::WRITE, &asn_info).inc();
                            crate::metrics::bytes_total(crate::metrics::WRITE, &asn_info)
                                .inc_by(size as u64);
                        }
                        Err(error) => {
                            let source = error.to_string();
                            crate::metrics::errors_total(crate::metrics::WRITE, &source, &asn_info)
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

        tokio::spawn(inner_task);

        let mut destinations = Vec::with_capacity(1);

        loop {
            // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
            // packet, which is the maximum value of 16 a bit integer.
            let mut buffer = buffer_pool.clone().alloc();

            tokio::select! {
                result = socket.recv_from(&mut *buffer) => {
                    let received_at = crate::time::UtcTimestamp::now();

                    match result {
                        Ok((_size, mut source)) => {
                            source.set_ip(source.ip().to_canonical());
                            let packet = crate::net::packet::DownstreamPacket { contents: buffer, source };

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
