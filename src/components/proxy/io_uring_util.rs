//! We have two cases in the proxy where io-uring is used that are _almost_ identical
//! so this just has a shared implementation of utilities
//!
//! Note there is also the QCMP loop, but that one is simpler and is different
//! enough that it doesn't make sense to share the same code

use crate::{net::maxmind_db::MetricsIpNetEntry, pool::PoolBuffer};
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

#[derive(Clone)]
pub enum PacketProcessor {
    Router {
        config: Arc<crate::config::Config>,
        sessions: Arc<crate::components::proxy::SessionPool>,
        error_sender: tokio::sync::mpsc::UnboundedSender<crate::components::proxy::PipelineError>,
    },
    SessionPool {
        pool: Arc<crate::components::proxy::SessionPool>,
    },
}

// if let Some(last_received_at) = last_received_at {
//     crate::metrics::packet_jitter(crate::metrics::WRITE, asn_info)
//         .set((received_at - *last_received_at).nanos());
// }
// *last_received_at = Some(received_at);

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

pub struct IoUringLoop {
    pub runtime: tokio::runtime::Runtime,
    /// Tokens for outstanding I/O ops
    tokens: slab::Slab<Token>,
    pending_packets: slab::Slab<PendingPacket>,
}

impl IoUringLoop {
    pub fn new(concurrent_sends: u16) -> crate::Result<Self> {}

    pub fn spawn(
        self,
        thread_name: impl Into<String>,
    ) -> crate::Result<tokio::sync::oneshot::Receiver<crate::Result<()>>> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        std::thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || {})?;

        Ok(rx)
    }
}
