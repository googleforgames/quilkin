use std::{os::fd::{AsRawFd, FromRawFd, OwnedFd}, sync::Arc};
use eyre::Context as _;
use super::UpstreamPacket as DownstreamToUpstreamPacket;

const SESSION_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl super::SessionPool {
    pub(super) fn spawn_session(
        self: Arc<Self>,
        socket: socket2::Socket,
        port: u16,
        downstream_receiver: tokio::sync::mpsc::Receiver<super::UpstreamPacket>,
    ) -> crate::Result<tokio::sync::oneshot::Receiver<crate::Result<()>>> {
        let pool = self;
        let id = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .max_blocking_threads(2)
            .worker_threads(3)
            .build()
            .context("failed to spawn io-uring tokio runtime for session")?;

        let _thread_span = uring_span!(tracing::debug_span!("session", id).or_current());
        let dispatcher = tracing::dispatcher::get_default(|d| d.clone());

        let (mut tx, rx) = tokio::sync::oneshot::channel();

        std::thread::Builder::new()
            .name(format!("session-{id}"))
            .spawn(move || {
                let _guard = tracing::dispatcher::set_default(&dispatcher);

                let shutdown_event =
                    unsafe { OwnedFd::from_raw_fd(libc::eventfd(0, 0)) };
                let shutdown_fd = shutdown_event.as_raw_fd();
                let shutdown = pool.shutdown_rx.clone();
                rt.spawn(async move {
                    let _ = shutdown.changed().await;
                    unsafe {
                        libc::eventfd_write(shutdown_fd, 1);
                    }
                });

                // Create an eventfd to notify the uring thread (this one) of a pending
                // write
                // SAFETY: syscall
                let downstream_event =
                    unsafe { OwnedFd::from_raw_fd(libc::eventfd(0, 0)) };
                let pending_sends =
                    Arc::new(parking_lot::Mutex::<Vec<DownstreamToUpstreamPacket>>::default());

                let downstream_pending = downstream_event.as_raw_fd();
                let psends = pending_sends.clone();
                rt.spawn(async move {
                    let _ = tx.send(());

                    while let Some(packet) = downstream_receiver.recv().await {
                        psends.lock().push(packet);
                        // Notify the uring thread that it has pending packets to send
                        // SAFETY: syscall
                        unsafe { libc::eventfd_write(downstream_pending, 1) };
                    }
                });

                // Used to notify the uring when a downstream packet has finished processing and we can perform another read
                // SAFETY: syscall
                let process_event = unsafe { OwnedFd::from_raw_fd(libc::eventfd(0, 0)) };

                let mut ring = io_uring::IoUring::new(2048).context("unable to create io uring")?;

                let (submitter, sq, mut cq) = ring.split();

                let mut loop_ctx = LoopCtx {
                    sq,
                    socket_fd: socket.raw_fd(),
                    socket,
                    backlog: Default::default(),
                    downstream_sends: Default::default(),
                    tokens: Default::default(),
                };

                let mut recv_msghdr = unsafe { std::mem::zeroed() };
                let mut io_vec = std::io::IoSliceMut::new(&mut []);
                let mut downstream_addr = unsafe { std::mem::zeroed() };

                let mut recv_ctx =
                    RecvCtx::new(&mut recv_msghdr, &mut io_vec, &mut downstream_addr);

                let mut last_received_at = None;
                let mut processed = 0;
                let mut pending = 0;

                let mut buf = buffer_pool.clone().alloc();
                loop_ctx.enqueue_downstream_recv(&mut recv_ctx, &mut buf);
                loop_ctx.enqueue_upstream_pending(upstream_event.as_raw_fd(), &mut pending);

                // Important to note, sync needs to be called for the loop to actually function
                loop_ctx.sync();

                // Just double buffer the pending writes for simplicity
                let mut double_pending_sends = Vec::new();

                // The core io uring loop
                loop {
                    match submitter.submit_and_wait(1) {
                        Ok(_) => {}
                        Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => {}
                        Err(err) => {
                            return Err(err).context("failed to submit io-uring operations");
                        }
                    }
                    cq.sync();

                    loop_ctx.process_backlog(&submitter)?;

                    // Now actually process all of the completed io requests
                    for cqe in &mut cq {
                        let ret = cqe.result();
                        let token_index = cqe.user_data() as usize;

                        let token = loop_ctx.remove(token_index);
                        match token {
                            Token::DownstreamRecv => {
                                if ret < 0 {
                                    let error = std::io::Error::from_raw_os_error(-ret);
                                    tracing::error!(%error, "error receiving packet");
                                    loop_ctx.enqueue_downstream_recv(&mut recv_ctx, &mut buf);
                                    continue;
                                }

                                buf.set_len(ret as usize);

                                let mut source = recv_ctx.addr.as_socket().unwrap();
                                source.set_ip(source.ip().to_canonical());

                                let packet =
                                    crate::components::proxy::packet_router::DownstreamPacket {
                                        received_at: crate::time::UtcTimestamp::now(),
                                        contents: std::mem::replace(
                                            &mut buf,
                                            buffer_pool.clone().alloc(),
                                        ),
                                        source,
                                    };

                                if let Some(last_received_at) = last_received_at {
                                    crate::metrics::packet_jitter(crate::metrics::READ, None)
                                        .set((packet.received_at - last_received_at).nanos());
                                }
                                last_received_at = Some(packet.received_at);

                                let pctx = process_ctx.clone();
                                rt.spawn(async move {
                                    Self::process_task(
                                        packet,
                                        source,
                                        worker_id,
                                        &pctx.config,
                                        &pctx.sessions,
                                        &pctx.error_sender,
                                    )
                                    .await;

                                    // Notify the uring loop that we finished processing the packet so it
                                    // can enqueue the next receive
                                    // SAFETY: syscall
                                    unsafe {
                                        libc::eventfd_write(process_event, 1);
                                    }
                                });

                                // Queue the wait for the processing to finish
                                loop_ctx
                                    .enqueue_downstream_processed(process_event, &mut processed);
                            }
                            Token::DownstreamProcessed => {
                                loop_ctx.enqueue_downstream_recv(&mut recv_ctx, &mut buf);
                            }
                            Token::UpstreamPending => {
                                double_pending_sends = std::mem::replace(
                                    &mut pending_sends.lock(),
                                    double_pending_sends,
                                );

                                loop_ctx.enqueue_upstream_pending(
                                    upstream_event.as_raw_fd(),
                                    &mut pending,
                                );

                                for pending in
                                    double_pending_sends.drain(0..double_pending_sends.len())
                                {
                                    loop_ctx.enqueue_downstream_send(pending);
                                }
                            }
                            Token::DownstreamSend { send_buf } => {
                                let packet = loop_ctx.pop_sent(send_buf);
                                let asn_info = packet.asn_info.as_ref();

                                if ret < 0 {
                                    let source =
                                        std::io::Error::from_raw_os_error(-ret).to_string();
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
                                } else if ret as usize != packet.data.len() {
                                    crate::metrics::packets_total(crate::metrics::WRITE, asn_info)
                                        .inc();
                                    crate::metrics::errors_total(
                                        crate::metrics::WRITE,
                                        "sent bytes != packet length",
                                        asn_info,
                                    )
                                    .inc();
                                } else {
                                    crate::metrics::packets_total(crate::metrics::WRITE, asn_info)
                                        .inc();
                                    crate::metrics::bytes_total(crate::metrics::WRITE, asn_info)
                                        .inc_by(ret as u64);
                                }
                            }
                        }
                    }

                    loop_ctx.sync();
                }
            });

        Ok(rx)

        uring_spawn!(
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
        )
    }
}
