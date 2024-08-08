//! We have two cases in the proxy where io-uring is used that are _almost_ identical
//! so this just has a shared implementation of utilities
//!
//! Note there is also the QCMP loop, but that one is simpler and is different
//! enough that it doesn't make sense to share the same code

use crate::{
    components::proxy,
    metrics,
    net::maxmind_db::MetricsIpNetEntry,
    pool::{FrozenPoolBuffer, PoolBuffer},
    time::UtcTimestamp,
};
use eyre::Context as _;
use io_uring::{squeue::Entry, types::Fd};
use socket2::SockAddr;
use std::{
    os::fd::{AsRawFd, FromRawFd},
    sync::Arc,
};

struct RecvPacket {
    /// The buffer filled with data during recv_from
    buffer: PoolBuffer,
    /// The IP of the sender
    source: std::net::SocketAddr,
}

struct SendPacket {
    /// The destination address of the packet
    destination: SockAddr,
    /// The packet data being sent
    buffer: FrozenPoolBuffer,
    /// The asn info for the sender, used for metrics
    asn_info: Option<MetricsIpNetEntry>,
}

/// A simple double buffer for queing packets that need to be sent, each enqueue
/// notifies an eventfd that sends are available
#[derive(Clone)]
struct PendingSends {
    packets: Arc<parking_lot::Mutex<Vec<SendPacket>>>,
    notify_fd: Fd,
}

impl PendingSends {
    pub fn new(notify_fd: Fd) -> Self {
        Self {
            packets: Default::default(),
            notify_fd,
        }
    }

    #[inline]
    pub fn push(&self, packet: SendPacket) {
        self.packets.lock().push(packet);

        // SAFETY: syscall, this _shouldn't_ ever cause problems, even if the fd
        // is invalid/closed
        unsafe {
            libc::eventfd_write(self.notify_fd.0, 1);
        }
    }

    #[inline]
    pub fn swap(&self, swap: Vec<SendPacket>) -> Vec<SendPacket> {
        std::mem::replace(&mut self.packets.lock(), swap)
    }
}

enum LoopPacketInner {
    Recv(RecvPacket),
    Send(SendPacket),
}

/// A packet that is currently on the io-uring loop, either being received or sent
#[repr(C)]
struct LoopPacket {
    msghdr: libc::msghdr,
    addr: libc::sockaddr_storage,
    packet: Option<LoopPacketInner>,
    io_vec: libc::iovec,
}

impl LoopPacket {
    #[inline]
    fn new() -> Self {
        Self {
            msghdr: unsafe { std::mem::zeroed() },
            packet: None,
            io_vec: libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            addr: unsafe { std::mem::zeroed() },
        }
    }

    #[inline]
    fn set_packet(&mut self, mut packet: LoopPacketInner) {
        match &mut packet {
            LoopPacketInner::Recv(recv) => {
                // For receives, the length of the buffer is the total capacity
                self.io_vec.iov_base = recv.buffer.as_mut_ptr().cast();
                self.io_vec.iov_len = recv.buffer.capacity();
            }
            LoopPacketInner::Send(send) => {
                // For sends, the length of the buffer is the actual number of initialized bytes,
                // and note that iov_base is a *mut even though for sends the buffer is not actually
                // mutated
                self.io_vec.iov_base = send.buffer.as_ptr() as *mut u8 as *mut _;
                self.io_vec.iov_len = send.buffer.len();

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        send.destination.as_ptr().cast(),
                        &mut self.addr,
                        1,
                    );
                }
            }
        }

        // Increment the refcount of the buffer to ensure it stays alive for the
        // duration of the I/O
        self.packet = Some(packet);

        self.msghdr.msg_iov = std::ptr::addr_of_mut!(self.io_vec);
        self.msghdr.msg_iovlen = 1;
        self.msghdr.msg_name = std::ptr::addr_of_mut!(self.addr).cast();
        self.msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as _;
    }

    #[inline]
    fn finalize_recv(mut self, ret: usize) -> RecvPacket {
        let LoopPacketInner::Recv(mut recv) = self.packet.take().unwrap() else {
            unreachable!("finalized a send packet")
        };

        let mut source = unsafe {
            SockAddr::new(
                self.addr,
                std::mem::size_of::<libc::sockaddr_storage>() as _,
            )
        }
        .as_socket()
        .unwrap();
        source.set_ip(source.ip().to_canonical());

        recv.source = source;
        recv.buffer.set_len(ret);
        recv
    }

    #[inline]
    fn finalize_send(mut self) -> SendPacket {
        let LoopPacketInner::Send(send) = self.packet.take().unwrap() else {
            unreachable!("finalized a recv packet")
        };

        send
    }
}

pub enum PacketProcessorCtx {
    Router {
        config: Arc<crate::config::Config>,
        sessions: Arc<crate::components::proxy::SessionPool>,
        error_sender: tokio::sync::mpsc::UnboundedSender<crate::components::proxy::PipelineError>,
        /// Receiver for upstream packets being sent to this downstream
        upstream_receiver: crate::components::proxy::sessions::DownstreamReceiver,
        worker_id: usize,
    },
    SessionPool {
        pool: Arc<crate::components::proxy::SessionPool>,
        downstream_receiver: tokio::sync::mpsc::Receiver<proxy::SendPacket>,
        port: u16,
    },
}

/// Spawns worker tasks
///
/// One task processes received packets, notifying the io-uring loop when a
/// packet finishes processing, the other receives packets to send and notifies
/// the io-uring loop when there are 1 or more packets available to be sent
fn spawn_workers(
    rt: &tokio::runtime::Runtime,
    ctx: PacketProcessorCtx,
    pending_sends: PendingSends,
    packet_processed_event: Fd,
    mut shutdown_rx: crate::ShutdownRx,
    shutdown_event: Fd,
) -> tokio::sync::mpsc::Sender<RecvPacket> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<RecvPacket>(1);

    // Spawn a task that just monitors the shutdown receiver to notify the io-uring loop to exit
    rt.spawn(async move {
        // The result is uninteresting, either a shutdown has been signalled, or all senders have been dropped
        // which equates to the same thing
        let _ = shutdown_rx.changed().await;
        unsafe {
            libc::eventfd_write(shutdown_event.0, 1);
        }
    });

    match ctx {
        PacketProcessorCtx::Router {
            config,
            sessions,
            error_sender,
            worker_id,
            upstream_receiver,
        } => {
            rt.spawn(async move {
                let mut last_received_at = None;

                while let Some(packet) = rx.recv().await {
                    let received_at = UtcTimestamp::now();
                    if let Some(last_received_at) = last_received_at {
                        metrics::packet_jitter(metrics::READ, &metrics::EMPTY)
                            .set((received_at - last_received_at).nanos());
                    }
                    last_received_at = Some(received_at);

                    let ds_packet = proxy::packet_router::DownstreamPacket {
                        contents: packet.buffer,
                        source: packet.source,
                    };

                    crate::components::proxy::packet_router::DownstreamReceiveWorkerConfig::process_task(
                        ds_packet,
                        worker_id,
                        &config,
                        &sessions,
                        &error_sender,
                    )
                    .await;

                    // SAFETY: syscall
                    unsafe {
                        libc::eventfd_write(packet_processed_event.0, 1);
                    }
                }
            });

            rt.spawn(async move {
                while let Ok(packet) = upstream_receiver.recv().await {
                    let packet = SendPacket {
                        destination: packet.destination.into(),
                        buffer: packet.data,
                        asn_info: packet.asn_info,
                    };
                    pending_sends.push(packet);
                }
            });
        }
        PacketProcessorCtx::SessionPool {
            pool,
            port,
            mut downstream_receiver,
        } => {
            rt.spawn(async move {
                let mut last_received_at = None;

                while let Some(packet) = rx.recv().await {
                    pool.process_received_upstream_packet(
                        packet.buffer,
                        packet.source,
                        port,
                        &mut last_received_at,
                    )
                    .await;

                    // SAFETY: syscall
                    unsafe {
                        libc::eventfd_write(packet_processed_event.0, 1);
                    }
                }
            });

            rt.spawn(async move {
                while let Some(packet) = downstream_receiver.recv().await {
                    let packet = SendPacket {
                        destination: packet.destination.into(),
                        buffer: packet.data,
                        asn_info: packet.asn_info,
                    };
                    pending_sends.push(packet);
                }
            });
        }
    }

    tx
}

#[inline]
fn empty_net_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
}

enum Token {
    /// Packet received
    Recv { key: usize },
    /// Packet sent
    Send { key: usize },
    /// Recv packet processed
    RecvPacketProcessed,
    /// One or more packets are ready to be sent
    PendingsSends,
    /// Loop shutdown requested
    Shutdown,
}

struct LoopCtx<'uring> {
    sq: io_uring::squeue::SubmissionQueue<'uring, Entry>,
    backlog: std::collections::VecDeque<Entry>,
    socket_fd: Fd,
    tokens: slab::Slab<Token>,
    /// Packets currently being received or sent in the io-uring loop
    loop_packets: slab::Slab<LoopPacket>,
}

impl<'uring> LoopCtx<'uring> {
    #[inline]
    fn sync(&mut self) {
        self.sq.sync();
    }

    /// Enqueues a downstream recv
    #[inline]
    fn enqueue_recv(&mut self, buffer: crate::pool::PoolBuffer) {
        let packet = LoopPacketInner::Recv(RecvPacket {
            buffer,
            source: empty_net_addr(),
        });

        let (key, msghdr) = {
            let entry = self.loop_packets.vacant_entry();
            let key = entry.key();
            let pp = entry.insert(LoopPacket::new());
            pp.set_packet(packet);
            (key, std::ptr::addr_of_mut!(pp.msghdr))
        };

        let token = self.tokens.insert(Token::Recv { key });
        self.push(
            io_uring::opcode::RecvMsg::new(self.socket_fd, msghdr)
                .build()
                .user_data(token as _),
        );
    }

    /// Enqueues the wait for the received packet finishing processing
    #[inline]
    fn enqueue_recv_processed(&mut self, process_event: Fd, buf: &mut u64) {
        let token = self.tokens.insert(Token::RecvPacketProcessed);
        self.push(
            io_uring::opcode::Read::new(process_event, buf as *mut u64 as *mut _, 8)
                .build()
                .user_data(token as _),
        );
    }

    #[inline]
    fn enqueue_pending_sends(&mut self, pending_sends: Fd, buf: &mut u64) {
        let token = self.tokens.insert(Token::PendingsSends);
        self.push(
            io_uring::opcode::Read::new(pending_sends, buf as *mut u64 as *mut _, 8)
                .build()
                .user_data(token as _),
        );
    }

    #[inline]
    fn enqueue_send(&mut self, packet: SendPacket) {
        // We rely on sends using state with stable addresses, but realistically we should
        // never be at capacity
        if self.loop_packets.capacity() - self.loop_packets.len() == 0 {
            metrics::errors_total(
                metrics::WRITE,
                "io-uring packet send slab is at capacity",
                &packet.asn_info.as_ref().into(),
            );
            return;
        }

        let (key, msghdr) = {
            let entry = self.loop_packets.vacant_entry();
            let key = entry.key();
            let pp = entry.insert(LoopPacket::new());
            pp.set_packet(LoopPacketInner::Send(packet));
            (key, std::ptr::addr_of!(pp.msghdr))
        };

        let token = self.tokens.insert(Token::Send { key });
        self.push(
            io_uring::opcode::SendMsg::new(self.socket_fd, msghdr)
                .build()
                .user_data(token as _),
        );
    }

    #[inline]
    fn pop_packet(&mut self, key: usize) -> LoopPacket {
        self.loop_packets.remove(key)
    }

    /// For now we have a backlog, but this would basically mean that we are receiving
    /// more upstream packets than we can send downstream, which should? never happen
    #[inline]
    fn process_backlog(&mut self, submitter: &io_uring::Submitter<'uring>) -> std::io::Result<()> {
        loop {
            if self.sq.is_full() {
                match submitter.submit() {
                    Ok(_) => (),
                    Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => break,
                    Err(err) => return Err(err),
                }
            }
            self.sq.sync();

            match self.backlog.pop_front() {
                Some(sqe) => unsafe {
                    let _ = self.sq.push(&sqe);
                },
                None => break,
            }
        }

        Ok(())
    }

    #[inline]
    fn push(&mut self, entry: Entry) {
        // SAFETY: syscall
        unsafe {
            if self.sq.push(&entry).is_err() {
                self.backlog.push_back(entry);
            }
        }
    }

    #[inline]
    fn remove(&mut self, token: usize) -> Token {
        self.tokens.remove(token)
    }
}

pub struct IoUringLoop {
    runtime: tokio::runtime::Runtime,
    socket: crate::net::DualStackLocalSocket,
    concurrent_sends: usize,
}

impl IoUringLoop {
    pub fn new(
        concurrent_sends: u16,
        socket: crate::net::DualStackLocalSocket,
    ) -> crate::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .max_blocking_threads(1)
            .worker_threads(3)
            .build()
            .context("failed to spawn io-uring tokio runtime")?;

        Ok(Self {
            runtime,
            concurrent_sends: concurrent_sends as _,
            socket,
        })
    }

    pub fn spawn(
        self,
        thread_name: String,
        ctx: PacketProcessorCtx,
        buffer_pool: Arc<crate::pool::BufferPool>,
        shutdown: crate::ShutdownRx,
    ) -> crate::Result<tokio::sync::oneshot::Receiver<()>> {
        let dispatcher = tracing::dispatcher::get_default(|d| d.clone());
        let (tx, rx) = tokio::sync::oneshot::channel();

        let rt = self.runtime;
        let socket = self.socket;
        let concurrent_sends = self.concurrent_sends;

        let mut ring = io_uring::IoUring::new((concurrent_sends + 3) as _)
            .context("unable to create io uring")?;

        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let _guard = tracing::dispatcher::set_default(&dispatcher);

                let tokens = slab::Slab::with_capacity(concurrent_sends + 1 + 1 + 1);
                let loop_packets = slab::Slab::with_capacity(concurrent_sends + 1);

                // Create an eventfd to notify the uring thread (this one) of
                // pending sends
                // SAFETY: syscall
                let pending_sends_event =
                    unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::eventfd(0, 0)) };
                let pending_sends_fd = Fd(pending_sends_event.as_raw_fd());
                let pending_sends = PendingSends::new(pending_sends_fd);
                // Just double buffer the pending writes for simplicity
                let mut double_pending_sends = Vec::new();

                // Used to notify the uring when a downstream packet has finished processing and we can perform another read
                // SAFETY: syscall
                let process_event =
                    unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::eventfd(0, 0)) };
                let process_event_fd = Fd(process_event.as_raw_fd());

                // SAFETY: syscall
                let shutdown_event =
                    unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::eventfd(0, 0)) };
                let shutdown_event_fd = Fd(shutdown_event.as_raw_fd());

                // When sending packets, this is the direction used when updating metrics
                let send_dir = if matches!(ctx, PacketProcessorCtx::Router { .. }) {
                    metrics::WRITE
                } else {
                    metrics::READ
                };

                // Spawn the worker tasks that process in an async context unlike
                // our io-uring loop below
                let process_packet_tx = spawn_workers(
                    &rt,
                    ctx,
                    pending_sends.clone(),
                    process_event_fd,
                    shutdown,
                    shutdown_event_fd,
                );

                let (submitter, sq, mut cq) = ring.split();

                let mut loop_ctx = LoopCtx {
                    sq,
                    socket_fd: socket.raw_fd(),
                    backlog: Default::default(),
                    loop_packets,
                    tokens,
                };

                let mut pending = 0;
                let mut processed = 0;
                let mut shutdown = 0u64;

                loop_ctx.enqueue_recv(buffer_pool.clone().alloc());
                loop_ctx.enqueue_pending_sends(pending_sends_fd, &mut pending);

                let token = loop_ctx.tokens.insert(Token::Shutdown);
                loop_ctx.push(
                    io_uring::opcode::Read::new(
                        shutdown_event_fd,
                        &mut shutdown as *mut u64 as *mut _,
                        8,
                    )
                    .build()
                    .user_data(token as _),
                );

                // Sync always needs to be called when entries have been pushed
                // onto the submission queue for the loop to actually function (ie, similar to await on futures)
                loop_ctx.sync();

                // Notify that we have set everything up
                let _ = tx.send(());

                // The core io uring loop
                'io: loop {
                    match submitter.submit_and_wait(1) {
                        Ok(_) => {}
                        Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => {}
                        Err(error) => {
                            tracing::error!(%error, "io-uring submit_and_wait failed");
                            return;
                        }
                    }
                    cq.sync();

                    if let Err(error) = loop_ctx.process_backlog(&submitter) {
                        tracing::error!(%error, "failed to process io-uring backlog");
                        return;
                    }

                    // Now actually process all of the completed io requests
                    for cqe in &mut cq {
                        let ret = cqe.result();
                        let token_index = cqe.user_data() as usize;

                        let token = loop_ctx.remove(token_index);
                        match token {
                            Token::Recv { key } => {
                                // Pop the packet regardless of whether we failed or not so that
                                // we don't consume a buffer slot forever
                                let packet = loop_ctx.pop_packet(key);

                                if ret < 0 {
                                    let error = std::io::Error::from_raw_os_error(-ret);
                                    tracing::error!(%error, "error receiving packet");
                                    loop_ctx.enqueue_recv(buffer_pool.clone().alloc());
                                    continue;
                                }

                                let packet = packet.finalize_recv(ret as usize);
                                if process_packet_tx.blocking_send(packet).is_err() {
                                    unreachable!("packet process thread has a pending packet");
                                }

                                // Queue the wait for the processing to finish
                                loop_ctx.enqueue_recv_processed(process_event_fd, &mut processed);
                            }
                            Token::RecvPacketProcessed => {
                                loop_ctx.enqueue_recv(buffer_pool.clone().alloc());
                            }
                            Token::PendingsSends => {
                                double_pending_sends = pending_sends.swap(double_pending_sends);

                                loop_ctx.enqueue_pending_sends(pending_sends_fd, &mut pending);

                                for pending in
                                    double_pending_sends.drain(0..double_pending_sends.len())
                                {
                                    loop_ctx.enqueue_send(pending);
                                }
                            }
                            Token::Send { key } => {
                                let packet = loop_ctx.pop_packet(key).finalize_send();
                                let asn_info = packet.asn_info.as_ref().into();

                                if ret < 0 {
                                    let source =
                                        std::io::Error::from_raw_os_error(-ret).to_string();
                                    metrics::errors_total(send_dir, &source, &asn_info).inc();
                                    metrics::packets_dropped_total(send_dir, &source, &asn_info)
                                        .inc();
                                } else if ret as usize != packet.buffer.len() {
                                    metrics::packets_total(send_dir, &asn_info).inc();
                                    metrics::errors_total(
                                        send_dir,
                                        "sent bytes != packet length",
                                        &asn_info,
                                    )
                                    .inc();
                                } else {
                                    metrics::packets_total(send_dir, &asn_info).inc();
                                    metrics::bytes_total(send_dir, &asn_info).inc_by(ret as u64);
                                }
                            }
                            Token::Shutdown => {
                                tracing::info!("io-uring loop shutdown requested");
                                break 'io;
                            }
                        }
                    }

                    loop_ctx.sync();
                }
            })?;

        Ok(rx)
    }
}
