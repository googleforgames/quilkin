impl super::SessionPool {
    pub(super) fn spawn_session(
        self: std::sync::Arc<Self>,
        socket: socket2::Socket,
        port: u16,
        downstream_receiver: tokio::sync::mpsc::Receiver<super::UpstreamPacket>,
    ) -> crate::Result<tokio::sync::oneshot::Receiver<crate::Result<()>>> {
        let pool = self;

        let rx = uring_spawn!(
            uring_span!(tracing::debug_span!("session pool")),
            async move {
                let mut last_received_at = None;
                let mut shutdown_rx = pool.shutdown_rx.clone();

                let socket = std::sync::Arc::new(DualStackLocalSocket::from_raw(raw_socket));
                let socket2 = socket.clone();

                uring_inner_spawn!(async move {
                    loop {
                        match downstream_receiver.recv().await {
                            None => {
                                crate::metrics::errors_total(
                                    crate::metrics::WRITE,
                                    "downstream channel closed",
                                    None,
                                )
                                .inc();
                                break;
                            }
                            Some(UpstreamPacket {
                                dest,
                                data,
                                asn_info,
                            }) => {
                                tracing::trace!(%dest, length = data.len(), "sending packet upstream");
                                let (result, _) = socket2.send_to(data, dest).await;
                                let asn_info = asn_info.as_ref();
                                match result {
                                    Ok(size) => {
                                        crate::metrics::packets_total(
                                            crate::metrics::READ,
                                            asn_info,
                                        )
                                        .inc();
                                        crate::metrics::bytes_total(crate::metrics::READ, asn_info)
                                            .inc_by(size as u64);
                                    }
                                    Err(error) => {
                                        tracing::trace!(%error, "sending packet upstream failed");
                                        let source = error.to_string();
                                        crate::metrics::errors_total(
                                            crate::metrics::READ,
                                            &source,
                                            asn_info,
                                        )
                                        .inc();
                                        crate::metrics::packets_dropped_total(
                                            crate::metrics::READ,
                                            &source,
                                            asn_info,
                                        )
                                        .inc();
                                    }
                                }
                            }
                        }
                    }

                    let _ = initialised.send(());
                });

                loop {
                    let buf = pool.buffer_pool.clone().alloc();
                    tokio::select! {
                        received = socket.recv_from(buf) => {
                            let (result, buf) = received;
                            match result {
                                Err(error) => {
                                    tracing::trace!(%error, "error receiving packet");
                                    crate::metrics::errors_total(crate::metrics::WRITE, &error.to_string(), None).inc();
                                },
                                Ok((_size, recv_addr)) => pool.process_received_upstream_packet(buf, recv_addr, port, &mut last_received_at).await,
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            tracing::debug!("Closing upstream socket loop");
                            return;
                        }
                        _ = &mut rx => {
                            tracing::debug!("Closing upstream socket loop, downstream closed");
                            return;
                        }
                    }
                }
            }
        );

        Ok(rx)
    }
}
