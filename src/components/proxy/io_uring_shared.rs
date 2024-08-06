//! We have two cases in the proxy where io-uring is used that are _almost_ identical
//! so this just has a shared implementation of utilities
//!
//! Note there is also the QCMP loop, but that one is simpler and is different
//! enough that it doesn't make sense to share the same code

use crate::{net::maxmind_db::MetricsIpNetEntry, metrics, time::UtcTimestamp, pool::PoolBuffer, components::proxy::sessions::{DownstreamPacket as UpstreamToDownstreamPacket, UpstreamPacket as DownstreamToUpstreamPacket};
use eyre::Context as _;
use io_uring::types::Fd;
use std::sync::Arc;

pub struct Packet {
    /// The address the packet was received from/being sent to
    pub address: socket2::SockAddr,
    /// The asn info for the sender or receiver
    pub asn_info: Option<MetricsIpNetEntry>,
    /// The actuall buffer being written to/read from
    pub buffer: PoolBuffer,
}

/// A simple double buffer for queing packets that need to be sent, each enqueue
/// notifies an eventfd that sends are available
#[derive(Clone)]
struct PendingSends {
    packets: Arc<parking_lot::Mutex<Vec<Packet>>>,
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
    pub fn push(&self, packet: Packet) {
        self.packets.lock().push(packet);

        // SAFETY: syscall, this _shouldn't_ ever cause problems, even if the fd
        // is invalid/closed
        unsafe {
            libc::eventfd_write(self.notify_fd.0, 1);
        }
    }

    #[inline]
    pub fn swap(&self, swap: Vec<Packet>) -> Vec<Packet> {
        std::mem::replace(&mut self.packets.lock(), swap)
    }
}

/// A packet that is currently on the io-uring loop, either being received or sent
#[repr(C)]
struct PendingPacket {
    msghdr: libc::msghdr,
    packet: Option<Packet>,
    io_vec: libc::iovec,
}

impl PendingPacket {
    #[inline]
    fn new() -> Self {
        Self {
            msghdr: unsafe { std::mem::zeroed() },
            packet: None,
            io_vec: libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 1,
            },
        }
    }

    #[inline]
    fn send(&mut self, packet: Packet) {
        // For sends, the length of the buffer is the actual number of initialized bytes
        let len = packet.buffer.len();
        self.set_packet(packet, len);
    }

    #[inline]
    fn recv(&mut self, packet: Packet) {
        // For receives, the length of the buffer is the total capacity
        let len = packet.buffer.capacity();
        self.set_packet(packet, len);
    }

    #[inline]
    fn set_packet(&mut self, packet: Packet, len: usize) {
        self.packet = Some(packet);
        let packet = self.packet.as_ref().unwrap();

        self.io_vec.iov_base = packet.buffer.as_mut_ptr().cast();
        self.io_vec.iov_len = len;
        self.msghdr.msg_iov = std::ptr::addr_of_mut!(self.io_vec);
        self.msghdr.msg_name = packet.address.as_ptr() as *mut libc::sockaddr as *mut _;
        self.msghdr.msg_namelen = packet.address.len();
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
        downstream_receiver: tokio::sync::mpsc::Receiver<DownstreamToUpstreamPacket>
        port: u16,
    },
}

/// Spawns an async task to process a received packet, records metrics for it,
/// and notifies the io-uring loop when it has finished
struct PacketProcessor {
    /// Timestamp of the last packet received, used to calculate jitter metrics
    timestamp: Option<crate::time::UtcTimestamp>,
    ctx: PacketProcessorCtx,
    /// eventfd we use to notify the io-uring loop when we are finished processing
    notify_fd: Fd,
}

/// Spawns an async task that processes recv packets, notifying the io-uring
/// loop when it has processed each packet.
fn spawn_packet_processor(rt: &tokio::runtime::Runtime, ctx: PacketProcessorCtx, notify_fd: Fd) -> tokio::sync::mpsc::BoundedSender<RecvPacket> {
    let (tx, rx) = tokio::sync::mpsc::bounded(1);

    match ctx {
        PacketProcessorCtx::Router { config, sessions, error_sender, worker_id } => {
            rt.spawn(async move {
                let mut last_received_at = None;

                while let Ok(packet) = rx.recv().await {

                    if let Some(last_received_at) = last_received_at {
                        metrics::packet_jitter(metrics::READ, None)
                            .set((packet.received_at - last_received_at).nanos());
                    }
                    last_received_at = Some(packet.received_at);

                    crate::components::proxy::packet_router::DownstreamReceiveWorkerConfig::process_task(
                        packet,
                        source,
                        worker_id,
                        &config,
                        &sessions,
                        &error_sender,
                    )
                    .await;

                    // SAFETY: syscall
                    unsafe {
                        libc::eventfd_write(notify_fd, 1);
                    }
                }
            });
        }
        PacketProcessorCtx::SessionPool { pool, port } => {
            rt.spawn(async move {
                let mut last_received_at = None;

                while let Ok(packet) = rx.recv().await {
                    pool.process_received_upstream_packet(packet.buffer, packet.addr, port, &mut last_received_at).await;
                    // SAFETY: syscall
                    unsafe {
                        libc::eventfd_write(notify_fd, 1);
                    }
                }
            });
        }
    }

    tx
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

pub enum IoUringContext {
    Router {
        config: Arc<crate::config::Config>,
        sessions: Arc<crate::components::proxy::SessionPool>,
        error_sender: tokio::sync::mpsc::UnboundedSender<crate::components::proxy::PipelineError>,
        worker_id: usize,
    }
}

pub struct IoUringLoop {
    runtime: tokio::runtime::Runtime,
    /// Tokens for outstanding I/O ops
    tokens: slab::Slab<Token>,
    pending_packets: slab::Slab<PendingPacket>,
    socket: crate::net::DualStackLocalSocket,
}

impl IoUringLoop {
    pub fn new(concurrent_sends: u16, socket: crate::net::DualStackLocalSocket) -> crate::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .max_blocking_threads(1)
            .worker_threads(2)
            .build()
            .context("failed to spawn io-uring tokio runtime")?;

        Ok(Self {
            runtime,
            tokens: slab::Slab::with_capacity(concurrent_sends as usize + 1 + 1 + 1),
            pending_packets: slab::Slab::with_capacity(concurrent_sends as usize + 1),
            socket,
        })
    }

    pub fn spawn(
        self,
        thread_name: String,
    ) -> crate::Result<tokio::sync::oneshot::Receiver<crate::Result<()>>> {
        let dispatcher = tracing::dispatcher::get_default(|d| d.clone());
        let (tx, rx) = tokio::sync::oneshot::channel();

        let rt = self.rt;

        std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                let _guard = tracing::dispatcher::set_default(&dispatcher);

                // Spawn an async task to convert async packet sends to a sync
                // buffer for the io-uring loop, for simplicity we use a simple
                // double buffer strategy so that we hold a lock for a single
                // exchange
                // Create an eventfd to notify the uring thread (this one) of
                // pending sends
                // SAFETY: syscall
                let pending_sends_event =
                    unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::eventfd(0, 0)) };
                let pending_sends =
                    Arc::new(parking_lot::Mutex::<Vec<SendPacket>>::default());

                // Spawn a task that receives packets from upstream (servers) and sends them
                // to the specified downstream receivers (clients)
                let pending_send_event = pending_sends_event.as_raw_fd();
                let psends = pending_sends.clone();

                


                rt.spawn(async move {
                    is_ready.notify_one();

                    loop {
                        match upstream_receiver.recv().await {
                            Ok(packet) => {
                                psends.lock().push(packet);
                                // Notify the uring thread that it has pending packets to send
                                // SAFETY: syscall
                                unsafe { libc::eventfd_write(pending_send_event, 1) };
                            }
                            Err(error) => {
                                tracing::trace!(%error, "error receiving packet");
                                metrics::errors_total(
                                    metrics::WRITE,
                                    &error.to_string(),
                                    None,
                                )
                                .inc();
                            }
                        }
                    }
                });

            })?;

        Ok(rx)
    }
}

//! io-uring implementation of the packet router, we roll our own implementation
//! based on io-uring instead of tokio-uring as it allows us to avoid a **ton**
//! of unnecessary heap allocations over the lifetime of a proxy

use std::{
    os::fd::{AsRawFd, FromRawFd},
    sync::Arc,
};

use crate::components::proxy::sessions::DownstreamPacket as UpstreamToDownstreamPacket;
use eyre::Context as _;
use io_uring::{squeue::Entry, types::Fd};

#[derive(Copy, Clone)]
enum Token {
    /// A packet has been received from a downstream client
    DownstreamRecv,
    /// The downstream packet has finished processing
    DownstreamProcessed,
    /// A packet from an upstream server is available to be sent
    UpstreamPending,
    /// A packet being sent from upstream -> downstream
    DownstreamSend { send_buf: usize },
}

#[repr(C)]
struct DownstreamSend {
    msghdr: libc::msghdr,
    io_vec: std::io::IoSlice<'static>,
    addr: socket2::SockAddr,
    packet: Option<UpstreamToDownstreamPacket>,
}

impl DownstreamSend {
    fn new(addr: std::net::SocketAddr) -> Self {
        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
        msghdr.msg_iovlen = 1;

        Self {
            msghdr,
            io_vec: std::io::IoSlice::new(&[]),
            addr: addr.into(),
            packet: None,
        }
    }

    #[inline]
    fn set_packet(&mut self, packet: UpstreamToDownstreamPacket) -> *const libc::msghdr {
        self.io_vec = packet.data.as_io_slice();
        self.packet = Some(packet);

        self.msghdr.msg_iov = std::ptr::addr_of!(self.io_vec) as *mut _;
        self.msghdr.msg_name = self.addr.as_ptr() as *mut _;
        self.msghdr.msg_namelen = self.addr.len();

        std::ptr::addr_of!(self.msghdr)
    }
}

struct LoopCtx<'uring> {
    sq: io_uring::squeue::SubmissionQueue<'uring, Entry>,
    backlog: std::collections::VecDeque<Entry>,
    /// Bound socket we use for sending and receiving to/from downstream clients
    socket: crate::net::DualStackLocalSocket,
    socket_fd: Fd,

    /// Current sends from upstream -> downstream
    downstream_sends: slab::Slab<DownstreamSend>,
}

impl<'uring> LoopCtx<'uring> {
    #[inline]
    fn sync(&mut self) {
        self.sq.sync();
    }

    /// Enqueues a downstream recv
    #[inline]
    fn enqueue_downstream_recv<'stack>(
        &mut self,
        ctx: &mut RecvCtx<'stack>,
        buf: &mut crate::pool::PoolBuffer,
    ) {
        *ctx.io_vec = buf.as_io_slice_mut();

        let token = self.tokens.insert(Token::DownstreamRecv);
        self.push(
            io_uring::opcode::RecvMsg::new(self.socket_fd, ctx.msghdr as *mut _)
                .build()
                .user_data(token as _),
        );
    }

    /// Enqueues the wait for the downstream packet finishing processing
    #[inline]
    fn enqueue_downstream_processed<'stack>(&mut self, process_event: i32, buf: &mut u64) {
        let token = self.tokens.insert(Token::DownstreamProcessed);
        self.push(
            io_uring::opcode::Read::new(Fd(process_event), buf as *mut u64 as *mut _, 8)
                .build()
                .user_data(token as _),
        );
    }

    #[inline]
    fn enqueue_upstream_pending(&mut self, upstream_pending: i32, buf: &mut u64) {
        let token = self.tokens.insert(Token::UpstreamPending);
        self.push(
            io_uring::opcode::Read::new(Fd(upstream_pending), buf as *mut u64 as *mut _, 8)
                .build()
                .user_data(token as _),
        );
    }

    #[inline]
    fn enqueue_downstream_send(&mut self, packet: UpstreamToDownstreamPacket) {
        // We rely on sends using state with stable addresses, but realistically we should
        // never be at capacity
        if self.downstream_sends.capacity() - self.downstream_sends.len() == 0 {
            crate::metrics::errors_total(
                crate::metrics::WRITE,
                "io-uring upstream -> downstream slab is at capacity",
                packet.asn_info.as_ref(),
            );
            return;
        }

        let (msghdr, send_buf) = {
            let send_token = self
                .downstream_sends
                .insert(DownstreamSend::new(packet.destination));
            let send = self.downstream_sends.get_mut(send_token).unwrap();
            (send.set_packet(packet), send_token)
        };

        let token = self.tokens.insert(Token::DownstreamSend { send_buf });

        self.push(
            io_uring::opcode::SendMsg::new(self.socket_fd, msghdr)
                .build()
                .user_data(token as _),
        );
    }

    #[inline]
    fn pop_sent(&mut self, send_buf: usize) -> UpstreamToDownstreamPacket {
        self.downstream_sends
            .remove(send_buf)
            .packet
            .take()
            .unwrap()
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

/// Context for a socket `recv_from`
///
/// One of the reasons we are using io-uring instead of tokio-uring is because
/// [`tokio_uring::recvfrom`](https://github.com/tokio-rs/tokio-uring/blob/bf9906d052299dd05c3d13671800cd1632b1ee67/src/io/recv_from.rs#L20-L54)
/// does **3** heap allocation for _every packet_. This is...way too much for a proxy.
///
/// Instead we take advantage of the fact that each io-uring thread only does 1
/// recv at a time meaning we can just use the stack
#[repr(C)]
struct RecvCtx<'stack> {
    msghdr: &'stack mut libc::msghdr,
    io_vec: &'stack mut std::io::IoSliceMut<'stack>,
    addr: &'stack mut socket2::SockAddr,
}

impl<'stack> RecvCtx<'stack> {
    fn new(
        msghdr: &'stack mut libc::msghdr,
        io_vec: &'stack mut std::io::IoSliceMut<'stack>,
        addr: &'stack mut socket2::SockAddr,
    ) -> Self {
        let mut this = Self {
            msghdr,
            io_vec,
            addr,
        };

        this.msghdr.msg_iov = this.io_vec.as_mut_ptr().cast();
        this.msghdr.msg_iovlen = 1;
        this.msghdr.msg_name = this.addr.as_ptr() as *mut libc::c_void;
        this.msghdr.msg_namelen = this.addr.len();

        this
    }
}

impl super::DownstreamReceiveWorkerConfig {
    pub async fn spawn(self) -> eyre::Result<Arc<tokio::sync::Notify>> {
        let Self {
            worker_id,
            upstream_receiver,
            port,
            config,
            sessions,
            error_sender,
            buffer_pool,
        } = self;

        let notify = Arc::new(tokio::sync::Notify::new());
        let is_ready = notify.clone();

        let _thread_span =
            uring_span!(tracing::debug_span!("receiver", id = worker_id).or_current());
        let dispatcher = tracing::dispatcher::get_default(|d| d.clone());

        let socket =
            crate::net::DualStackLocalSocket::new(port).context("failed to bind socket")?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .max_blocking_threads(2)
            .worker_threads(2)
            .build()
            .context("failed to spawn io-uring tokio runtime")?;

        #[derive(Clone)]
        struct ProcessCtx {
            config: Arc<crate::config::Config>,
            sessions: Arc<crate::components::proxy::SessionPool>,
            error_sender:
                tokio::sync::mpsc::UnboundedSender<crate::components::proxy::PipelineError>,
        }

        let process_ctx = ProcessCtx {
            config,
            sessions,
            error_sender,
        };

        std::thread::Builder::new()
            .name(format!("io-uring-{worker_id}"))
            .spawn(move || -> eyre::Result<()> {
                let _guard = tracing::dispatcher::set_default(&dispatcher);

                // Create an eventfd to notify the uring thread (this one) of a pending
                // write
                // SAFETY: syscall
                let upstream_event =
                    unsafe { std::os::fd::OwnedFd::from_raw_fd(libc::eventfd(0, 0)) };
                let pending_sends =
                    Arc::new(parking_lot::Mutex::<Vec<UpstreamToDownstreamPacket>>::default());

                // Spawn a task that receives packets from upstream (servers) and sends them
                // to the specified downstream receivers (clients)
                let upstream_pending = upstream_event.as_raw_fd();
                let psends = pending_sends.clone();
                rt.spawn(async move {
                    is_ready.notify_one();

                    loop {
                        match upstream_receiver.recv().await {
                            Ok(packet) => {
                                psends.lock().push(packet);
                                // Notify the uring thread that it has pending packets to send
                                // SAFETY: syscall
                                unsafe { libc::eventfd_write(upstream_pending, 1) };
                            }
                            Err(error) => {
                                tracing::trace!(%error, "error receiving packet");
                                crate::metrics::errors_total(
                                    crate::metrics::WRITE,
                                    &error.to_string(),
                                    None,
                                )
                                .inc();
                            }
                        }
                    }
                });

                // Used to notify the uring when a downstream packet has finished processing and we can perform another read
                // SAFETY: syscall
                let process_event = unsafe { libc::eventfd(0, 0) };

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

                Ok(())
            });

        Ok(notify)
    }
}
