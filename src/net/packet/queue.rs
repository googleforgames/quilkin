use std::sync::Arc;

pub(crate) type PacketQueue = (PacketQueueSender, crate::net::io::Receiver);

pub(crate) fn queue(
    capacity: usize,
    backend: crate::net::io::Backend,
) -> std::io::Result<PacketQueue> {
    let (notify, rx) = backend.queue()?;

    Ok((
        PacketQueueSender {
            packets: Arc::new(parking_lot::Mutex::new(Vec::with_capacity(capacity))),
            notify,
        },
        rx,
    ))
}

/// A simple packet queue that signals when a packet is pushed
///
/// For `io_uring` this notifies an eventfd that will be processed on the next
/// completion loop
#[derive(Clone)]
pub struct PacketQueueSender {
    packets: Arc<parking_lot::Mutex<Vec<SendPacket>>>,
    notify: crate::net::io::Notifier,
}

impl PacketQueueSender {
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.packets.lock().capacity()
    }

    /// Pushes a packet onto the queue to be sent, signalling a sender that
    /// it's available
    #[inline]
    pub fn push(&self, packet: SendPacket) {
        self.packets.lock().push(packet);
        self.notify.notify();
    }

    /// Swaps the current queue with an empty one so we only lock for a pointer swap
    #[inline]
    pub(crate) fn swap(&self, mut swap: Vec<SendPacket>) -> Vec<SendPacket> {
        swap.clear();
        std::mem::replace(&mut self.packets.lock(), swap)
    }
}

pub struct SendPacket {
    /// The destination address of the packet
    pub destination: socket2::SockAddr,
    /// The packet data being sent
    pub data: crate::collections::FrozenPoolBuffer,
    /// The asn info for the sender, used for metrics
    pub asn_info: Option<crate::net::maxmind_db::MetricsIpNetEntry>,
}
