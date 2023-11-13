pub use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{atomic, mpsc, Arc},
};

pub const READ_QUILKIN_PORT: u16 = 9001;
pub const WRITE_QUILKIN_PORT: u16 = 9002;

pub const NUMBER_OF_PACKETS: u16 = 10_000;

pub const PACKET_SIZES: &[usize] = &[
    254,  // Half IPv4 MTU.
    508,  // IPv4 MTU.
    1500, // Ethernet MTU.
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

#[inline]
pub fn spawn<F>(name: impl Into<String>, func: F) -> std::thread::JoinHandle<()>
where
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.into())
        .spawn(func)
        .unwrap()
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
    pub num_packets: u16,
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
const CHUNK_SIZE: usize = 8 * 1024;

const fn batch_size(packet_size: usize) -> u16 {
    (CHUNK_SIZE / packet_size) as u16
}

/// Runs a loop, reading from the socket until all the expected number of bytes (based on packet count and size)
/// have been successfully received.
///
/// If the recv would block, a message is sent to request more bytes be sent to the socket,
/// we do this because while recv will fail if the timeout is surpassed and there is no
/// data to read, send (at least on linux) will never block on loopback even if there
/// not enough room in the ring buffer to hold the specified bytes
pub fn read_to_end<const N: usize>(
    socket: &UdpSocket,
    tx: &mpsc::Sender<ReadLoopMsg>,
    packet_count: u16,
) {
    let mut packet = [0; N];

    let mut num_packets = 0;
    let mut size_packets = 0;

    let expected = packet_count as usize * N;

    let batch_size = batch_size(N);

    struct Batch {
        received: usize,
        range: std::ops::Range<u16>,
    }

    let mut batch_i = 0u16;
    let mut batch_range = || -> std::ops::Range<u16> {
        let start = batch_size * batch_i;

        if start > packet_count {
            return 0..0;
        }

        batch_i += 1;
        start..(start + batch_size).min(packet_count)
    };

    // We can have a max of 2 batches in flight at a time
    let mut batches = [
        Batch {
            received: 0,
            range: batch_range(),
        },
        Batch {
            received: 0,
            range: batch_range(),
        },
    ];

    while size_packets < expected {
        let length = match socket.recv_from(&mut packet) {
            Ok(t) => t.0,
            Err(ref err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                continue;
            }
            Err(err) => panic!("failed waiting for packet: {err}"),
        };

        assert_eq!(length, N);

        {
            let seq = (packet[1] as u16) << 8 | packet[0] as u16;

            let batch = batches.iter_mut().find(|b| b.range.contains(&seq)).unwrap();

            batch.received += 1;
            if batch.received == batch.range.len() {
                batch.received = 0;
                batch.range = batch_range();

                if tx
                    .send(ReadLoopMsg::Acked(PacketStats {
                        num_packets,
                        size_packets,
                    }))
                    .is_err()
                {
                    return;
                }
            }
        }

        num_packets += 1;
        size_packets += length;
    }

    match socket.recv_from(&mut packet) {
        Ok(t) => panic!("writer sent more data than was intended: {t:?}"),
        Err(ref err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
            let _ = tx.send(ReadLoopMsg::Finished(PacketStats {
                num_packets,
                size_packets,
            }));
        }
        Err(err) => panic!("failed waiting for packet: {err}"),
    }
}

pub struct Writer<const N: usize> {
    socket: UdpSocket,
    destination: SocketAddr,
    rx: mpsc::Receiver<ReadLoopMsg>,
}

impl<const N: usize> Writer<N> {
    pub fn new(
        socket: UdpSocket,
        destination: SocketAddr,
        rx: mpsc::Receiver<ReadLoopMsg>,
    ) -> Self {
        Self {
            socket,
            destination,
            rx,
        }
    }

    /// Waits until a write is received by the specified socket
    pub fn wait_ready(&self, quilkin: QuilkinLoop, reader: &UdpSocket) -> QuilkinLoop {
        const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

        let start = std::time::Instant::now();

        let send_packet = [0xaa; 1];
        let mut recv_packet = [0x00; 1];

        // Temporarily make the socket blocking
        reader.set_nonblocking(false).unwrap();
        reader
            .set_read_timeout(Some(std::time::Duration::from_millis(10)))
            .unwrap();

        while start.elapsed() < MAX_WAIT {
            self.socket.send_to(&send_packet, self.destination).unwrap();

            match reader.recv_from(&mut recv_packet) {
                Ok(_) => {
                    assert_eq!(send_packet, recv_packet);

                    // Drain until block just in case
                    loop {
                        match reader.recv_from(&mut recv_packet) {
                            Ok(_) => {}
                            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                reader.set_nonblocking(true).unwrap();
                                reader.set_read_timeout(None).unwrap();
                                return quilkin;
                            }
                            Err(err) => {
                                panic!("failed to drain read socket: {err:?}");
                            }
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    println!("debugger might have attached");
                }
                Err(err) => {
                    panic!("failed to wait on read socket: {err:?}");
                }
            }
        }

        panic!("waited for {MAX_WAIT:?} for quilkin");
    }

    pub fn write_all(&self, packet_count: u16) -> bool {
        let batch_size = batch_size(N);

        let mut packet_buf = [0xffu8; N];

        let mut send_batch = |sent: u16| -> u16 {
            let to_send = (packet_count - sent).min(batch_size);

            for seq in sent..sent + to_send {
                let b = seq.to_ne_bytes();
                packet_buf[0] = b[0];
                packet_buf[1] = b[1];

                self.socket.send_to(&packet_buf, self.destination).unwrap();
            }

            to_send
        };

        let mut sent_packets = 0;

        // Queue 2 batches at the beginning, giving the reader enough work to do
        // after the initial batch has been read
        sent_packets += send_batch(sent_packets);
        sent_packets += send_batch(sent_packets);

        let mut finished = false;
        while let Ok(msg) = self.rx.recv() {
            match msg {
                ReadLoopMsg::Blocked(ps) => {
                    panic!("reader blocked {ps:?}");
                }
                ReadLoopMsg::Acked(ps) => {
                    if sent_packets < packet_count {
                        assert!(sent_packets > ps.num_packets);
                        sent_packets += send_batch(sent_packets);
                    }
                }
                ReadLoopMsg::Finished(ps) => {
                    assert_eq!(sent_packets, ps.num_packets);
                    assert_eq!(ps.size_packets, N * packet_count as usize);
                    finished = true;
                    break;
                }
            }
        }

        finished
    }
}

#[allow(dead_code)]
pub struct QuilkinLoop {
    shutdown: Option<quilkin::ShutdownTx>,
    thread: Option<std::thread::JoinHandle<()>>,
    port: u16,
    endpoint: SocketAddr,
}

impl QuilkinLoop {
    /// Run and instance of quilkin that sends and receives data from the given address.
    pub fn spinup(port: u16, endpoint: SocketAddr) -> Self {
        Self::spinup_inner(port, endpoint)
    }

    #[allow(dead_code)]
    fn reinit(self) -> Self {
        let port = self.port;
        let endpoint = self.endpoint;

        drop(self);

        Self::spinup_inner(port, endpoint)
    }

    fn spinup_inner(port: u16, endpoint: SocketAddr) -> Self {
        let (shutdown_tx, shutdown_rx) =
            quilkin::make_shutdown_channel(quilkin::ShutdownKind::Benching);

        let thread = spawn("quilkin", move || {
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
            port,
            endpoint,
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
