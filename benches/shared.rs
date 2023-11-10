pub use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{atomic, mpsc, Arc},
};

pub const READ_QUILKIN_PORT: u16 = 9001;
pub const WRITE_QUILKIN_PORT: u16 = 9002;

pub const MESSAGE_SIZE: usize = 0xffff;
pub const NUMBER_OF_PACKETS: usize = 10_000;

pub const PACKETS: &[&[u8]] = &[
    // Half IPv4 MTU.
    &[0xffu8; 254],
    // IPv4 MTU.
    &[0xffu8; 508],
    // Ethernet MTU.
    &[0xffu8; 1500],
];

pub fn make_socket(addr: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind(addr).expect("failed to bind");
    // socket
    //     .set_read_timeout(Some(std::time::Duration::from_millis(1)))
    //     .expect("failed to set read timeout");
    socket
        .set_nonblocking(true)
        .expect("failed to set non-blocking");
    socket
}

#[derive(Debug)]
pub enum ReadLoopMsg {
    #[allow(dead_code)]
    Blocked(PacketStats),
    Acked(PacketStats),
    Finished(PacketStats),
}

#[derive(Debug)]
pub struct PacketStats {
    /// Number of individual receives that were completed
    pub num_packets: usize,
    /// Total number of bytes received
    pub size_packets: usize,
}

#[inline]
pub fn channel() -> (mpsc::Sender<ReadLoopMsg>, mpsc::Receiver<ReadLoopMsg>) {
    mpsc::channel()
}

#[inline]
pub fn socket_pair(write: Option<u16>, read: Option<u16>) -> (UdpSocket, UdpSocket) {
    let w = make_socket((Ipv4Addr::LOCALHOST, write.unwrap_or_default()).into());
    let r = make_socket((Ipv4Addr::LOCALHOST, read.unwrap_or_default()).into());

    (w, r)
}

/// Writes never block even if the kernel's ring buffer is full, so we occasionally
/// ack chunks so the writer isn't waiting until the reader is blocked due to
/// ring buffer exhaustion in case
const CHUNK_SIZE: usize = 32 * 1024;
const ENABLE_GSO: bool = false;

const fn batch_size(packet_size: usize) -> usize {
    const MAX_GSO_SEGMENTS: usize = 64;

    let max_packets = CHUNK_SIZE / packet_size;
    if !ENABLE_GSO {
        return max_packets;
    }

    // No min in const :(
    if max_packets < MAX_GSO_SEGMENTS {
        max_packets
    } else {
        MAX_GSO_SEGMENTS
    }
}

/// Runs a loop, reading from the socket until all the expected number of bytes (based on packet count and size)
/// have been successfully received.
///
/// If the recv would block, a message is sent to request more bytes be sent to the socket,
/// we do this because while recv will fail if the timeout is surpassed and there is no
/// data to read, send (at least on linux) will never block on loopback even if there
/// not enough room in the ring buffer to hold the specified bytes
pub fn read_to_end(
    socket: &UdpSocket,
    tx: &mpsc::Sender<ReadLoopMsg>,
    packet_count: usize,
    packet_size: usize,
) {
    let mut packet = [0; MESSAGE_SIZE];

    let mut num_packets = 0;
    let mut size_packets = 0;

    let expected = packet_count * packet_size;

    let batch_size = batch_size(packet_size);
    let mut batch_end = batch_size;

    while size_packets < expected {
        let length = match socket.recv_from(&mut packet) {
            Ok(t) => t.0,
            Err(ref err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                continue;
            }
            Err(err) => panic!("failed waiting for packet: {err}"),
        };

        num_packets += 1;
        size_packets += length;

        if num_packets >= batch_end {
            if tx
                .send(ReadLoopMsg::Acked(PacketStats {
                    num_packets,
                    size_packets,
                }))
                .is_err()
            {
                return;
            }

            batch_end += batch_size;
        }
    }

    let _ = tx.send(ReadLoopMsg::Finished(PacketStats {
        num_packets,
        size_packets,
    }));
}

pub struct Writer {
    #[cfg(target_os = "linux")]
    socket: socket2::Socket,
    #[cfg(not(target_os = "linux"))]
    socket: UdpSocket,
    destination: SocketAddr,
    rx: mpsc::Receiver<ReadLoopMsg>,
    batch_size: usize,
    packet: &'static [u8],
    #[cfg(unix)]
    slices: Vec<std::io::IoSlice<'static>>,
}

impl Writer {
    pub fn new(
        socket: UdpSocket,
        destination: SocketAddr,
        rx: mpsc::Receiver<ReadLoopMsg>,
        packet: &'static [u8],
    ) -> Self {
        let batch_size = batch_size(packet.len());

        #[cfg(target_os = "linux")]
        let (socket, slices) = {
            let socket = socket2::Socket::from(socket);

            (socket, vec![std::io::IoSlice::new(packet); batch_size])
        };

        Self {
            socket,
            destination,
            rx,
            batch_size,
            packet,
            #[cfg(target_os = "linux")]
            slices,
        }
    }

    pub fn write_all(&self, packet_count: usize) -> bool {
        use std::{mem, ptr};

        // The value of the auxiliary data to put in the control message.
        let segment_size = self.packet.len() as u16;

        #[cfg(target_os = "linux")]
        let (dst, buf, layout) = {
            // The number of bytes needed for this control message.
            let cmsg_size = unsafe { libc::CMSG_SPACE(mem::size_of_val(&segment_size) as _) };
            let layout = std::alloc::Layout::from_size_align(
                cmsg_size as usize,
                mem::align_of::<libc::cmsghdr>(),
            )
            .unwrap();
            let buf = unsafe { std::alloc::alloc(layout) };

            (socket2::SockAddr::from(self.destination), buf, layout)
        };

        let send_batch = |received: usize| {
            let to_send = (packet_count - received).min(self.batch_size);

            // GSO, see https://github.com/flub/socket-use/blob/main/src/bin/sendmsg_gso.rs
            #[cfg(target_os = "linux")]
            {
                if !ENABLE_GSO {
                    for _ in 0..to_send {
                        self.socket.send_to(self.packet, &dst).unwrap();
                    }
                    return;
                }

                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };

                // Set the single destination and the payloads of each datagram
                msg.msg_name = dst.as_ptr() as *mut _;
                msg.msg_namelen = dst.len();
                msg.msg_iov = self.slices.as_ptr() as *mut _;
                msg.msg_iovlen = to_send;

                msg.msg_control = buf as *mut _;
                msg.msg_controllen = layout.size();

                let cmsg: &mut libc::cmsghdr = unsafe {
                    let cmsg = libc::CMSG_FIRSTHDR(&msg);
                    let cmsg_zeroed: libc::cmsghdr = mem::zeroed();
                    ptr::copy_nonoverlapping(&cmsg_zeroed, cmsg, 1);
                    cmsg.as_mut().unwrap()
                };
                cmsg.cmsg_level = libc::SOL_UDP;
                cmsg.cmsg_type = libc::UDP_SEGMENT;
                cmsg.cmsg_len =
                    unsafe { libc::CMSG_LEN(mem::size_of_val(&segment_size) as _) } as libc::size_t;
                unsafe { ptr::write(libc::CMSG_DATA(cmsg) as *mut u16, segment_size) };

                use std::os::fd::AsRawFd;
                if unsafe { libc::sendmsg(self.socket.as_raw_fd(), &msg, 0) } == -1 {
                    panic!("failed to send batch: {}", std::io::Error::last_os_error());
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                for _ in 0..to_send {
                    self.socket.send_to(self.packet, self.destination).unwrap();
                }
            }
        };

        // Queue 2 batches at the beginning, giving the reader enough work to do
        // after the initial batch has been read
        send_batch(0);
        send_batch(self.batch_size);

        let mut finished = false;
        while let Ok(msg) = self.rx.recv() {
            match msg {
                ReadLoopMsg::Blocked(ps) => {
                    panic!("reader blocked {ps:?}");
                }
                ReadLoopMsg::Acked(ps) => {
                    send_batch(ps.num_packets);
                }
                ReadLoopMsg::Finished(ps) => {
                    assert_eq!(ps.size_packets, self.packet.len() * packet_count);
                    finished = true;
                    break;
                }
            }
        }

        // Don't leak the buf
        unsafe { std::alloc::dealloc(buf, layout) };
        finished
    }
}

pub struct QuilkinLoop {
    shutdown: Option<quilkin::ShutdownTx>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl QuilkinLoop {
    /// Run and instance of quilkin that sends and receives data from the given address.
    pub fn spinup(port: u16, endpoint: SocketAddr) -> Self {
        let (shutdown_tx, shutdown_rx) =
            quilkin::make_shutdown_channel(quilkin::ShutdownKind::Benching);

        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let config = Arc::new(quilkin::Config::default());
            config.clusters.modify(|clusters| {
                clusters
                    .insert_default([quilkin::net::endpoint::Endpoint::new(endpoint.into())].into())
            });

            let proxy = quilkin::cli::Proxy {
                port,
                qcmp_port: runtime
                    .block_on(quilkin::test::available_addr(
                        &quilkin::test::AddressType::Random,
                    ))
                    .port(),
                ..<_>::default()
            };

            runtime.block_on(async move {
                let admin = quilkin::cli::Admin::Proxy(<_>::default());
                proxy.run(config, admin, shutdown_rx).await.unwrap();
            });
        });

        Self {
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }
}

impl Drop for QuilkinLoop {
    fn drop(&mut self) {
        let Some(stx) = self.shutdown.take() else {
            return;
        };
        stx.send(quilkin::ShutdownKind::Benching).unwrap();
        self.thread.take().unwrap().join().unwrap();
    }
}
