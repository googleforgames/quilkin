//! The reference implementation is used for non-Linux targets

impl super::DownstreamReceiveWorkerConfig {
    pub async fn spawn(self) -> eyre::Result<tokio::sync::oneshot::Receiver<crate::Result<()>>> {
        let Self {
            worker_id,
            upstream_receiver,
            port,
            config,
            sessions,
            error_sender,
            buffer_pool,
        } = self;

        let (tx, rx) = tokio::sync::oneshot::channel();

        let thread_span =
            uring_span!(tracing::debug_span!("receiver", id = worker_id).or_current());

        let worker = uring_spawn!(thread_span, async move {
            let mut last_received_at = None;
            let socket = crate::net::DualStackLocalSocket::new(port)
                .unwrap()
                .make_refcnt();

            tracing::trace!(port, "bound worker");
            let send_socket = socket.clone();

            let inner_task = async move {
                tx.send(Ok(()));

                loop {
                    tokio::select! {
                        result = upstream_receiver.recv() => {
                            match result {
                                Err(error) => {
                                    tracing::trace!(%error, "error receiving packet");
                                    crate::metrics::errors_total(
                                        crate::metrics::WRITE,
                                        &error.to_string(),
                                        None,
                                        )
                                        .inc();
                                }
                                Ok((data, asn_info, send_addr)) => {
                                    let (result, _) = send_socket.send_to(data, send_addr).await;
                                    let asn_info = asn_info.as_ref();
                                    match result {
                                        Ok(size) => {
                                            crate::metrics::packets_total(crate::metrics::WRITE, asn_info)
                                                .inc();
                                            crate::metrics::bytes_total(crate::metrics::WRITE, asn_info)
                                                .inc_by(size as u64);
                                        }
                                        Err(error) => {
                                            let source = error.to_string();
                                            crate::metrics::errors_total(
                                                crate::metrics::WRITE,
                                                &source,
                                                asn_info,
                                                )
                                                .inc();
                                            crate::metrics::packets_dropped_total(
                                                crate::metrics::WRITE,
                                                &source,
                                                asn_info,
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

            loop {
                // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
                // packet, which is the maximum value of 16 a bit integer.
                let buffer = buffer_pool.clone().alloc();

                let (result, contents) = socket.recv_from(buffer).await;

                match result {
                    Ok((_size, mut source)) => {
                        source.set_ip(source.ip().to_canonical());
                        let packet = super::DownstreamPacket {
                            received_at: crate::time::UtcTimestamp::now(),
                            contents,
                            source,
                        };

                        if let Some(last_received_at) = last_received_at {
                            crate::metrics::packet_jitter(crate::metrics::READ, None)
                                .set((packet.received_at - last_received_at).nanos());
                        }
                        last_received_at = Some(packet.received_at);

                        Self::process_task(packet, worker_id, &config, &sessions, &error_sender)
                            .await;
                    }
                    Err(error) => {
                        tracing::error!(%error, "error receiving packet");
                        return;
                    }
                }
            }
        });

        use eyre::WrapErr as _;
        worker.await.context("failed to spawn receiver task")??;
        Ok(rx)
    }
}
