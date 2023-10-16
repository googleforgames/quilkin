use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{atomic, mpsc, Arc};
use std::thread::sleep;
use std::time;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use once_cell::sync::Lazy;
use quilkin::test_utils::AddressType;

const MESSAGE_SIZE: usize = 0xffff;
const DEFAULT_MESSAGE: [u8; 0xffff] = [0xff; 0xffff];
const BENCH_LOOP_ADDR: &str = "127.0.0.1:8002";
const FEEDBACK_LOOP_ADDR: &str = "127.0.0.1:8001";
const QUILKIN_ADDR: &str = "127.0.0.1:8000";
const NUMBER_OF_PACKETS: usize = 10_000;

const PACKETS: &[&[u8]] = &[
    // Half IPv4 MTU.
    &[0xffu8; 254],
    // IPv4 MTU.
    &[0xffu8; 508],
    // Ethernet MTU.
    &[0xffu8; 1500],
];

/// Run and instance of quilkin that sends and received data
/// from the given address.
fn run_quilkin(port: u16, endpoint: SocketAddr) {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let config = Arc::new(quilkin::Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default([quilkin::endpoint::Endpoint::new(endpoint.into())].into())
        });

        let proxy = quilkin::cli::Proxy {
            port,
            qcmp_port: runtime
                .block_on(quilkin::test_utils::available_addr(&AddressType::Random))
                .port(),
            ..<_>::default()
        };

        runtime.block_on(async move {
            let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel::<()>(());
            let admin = quilkin::cli::Admin::Proxy(<_>::default());
            proxy.run(config, admin, shutdown_rx).await.unwrap();
        });
    });
}

static THROUGHPUT_SERVER_INIT: Lazy<()> = Lazy::new(|| {
    run_quilkin(8000, FEEDBACK_LOOP_ADDR.parse().unwrap());
});

static FEEDBACK_LOOP: Lazy<()> = Lazy::new(|| {
    std::thread::spawn(|| {
        let socket = UdpSocket::bind(FEEDBACK_LOOP_ADDR).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();

        loop {
            let mut packet = [0; MESSAGE_SIZE];
            let (_, addr) = socket.recv_from(&mut packet).unwrap();
            let length = packet.iter().position(|&x| x == 0).unwrap_or(packet.len());
            let packet = &packet[..length];
            assert_eq!(packet, &DEFAULT_MESSAGE[..length]);
            socket.send_to(packet, addr).unwrap();
        }
    });
});

fn throughput_benchmark(c: &mut Criterion) {
    Lazy::force(&FEEDBACK_LOOP);
    Lazy::force(&THROUGHPUT_SERVER_INIT);
    // Sleep to give the servers some time to warm-up.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let socket = UdpSocket::bind(BENCH_LOOP_ADDR).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .unwrap();
    let mut packet = [0; MESSAGE_SIZE];

    let mut group = c.benchmark_group("throughput");
    for message in PACKETS {
        group.sample_size(NUMBER_OF_PACKETS);
        group.sampling_mode(criterion::SamplingMode::Flat);
        group.throughput(criterion::Throughput::Bytes(message.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("direct", format!("{} bytes", message.len())),
            &message,
            |b, message| {
                b.iter(|| {
                    socket.send_to(message, FEEDBACK_LOOP_ADDR).unwrap();
                    socket.recv_from(&mut packet).unwrap();
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("quilkin", format!("{} bytes", message.len())),
            &message,
            |b, message| {
                b.iter(|| {
                    socket.send_to(message, QUILKIN_ADDR).unwrap();
                    socket.recv_from(&mut packet).unwrap();
                })
            },
        );
    }
    group.finish();
}

const WRITE_LOOP_ADDR: &str = "127.0.0.1:8003";
const READ_LOOP_ADDR: &str = "127.0.0.1:8004";

const READ_QUILKIN_PORT: u16 = 9001;
static READ_SERVER_INIT: Lazy<()> = Lazy::new(|| {
    run_quilkin(READ_QUILKIN_PORT, READ_LOOP_ADDR.parse().unwrap());
});

const WRITE_QUILKIN_PORT: u16 = 9002;
static WRITE_SERVER_INIT: Lazy<()> = Lazy::new(|| {
    run_quilkin(WRITE_QUILKIN_PORT, WRITE_LOOP_ADDR.parse().unwrap());
});

/// Binds a socket to `addr`, and waits for an initial packet to be sent to it to establish
/// a connection. After which any `Vec<u8>` sent to the returned channel will result in that
/// data being send via that connection - thereby skipping the proxy `read` operation.
fn write_feedback(addr: SocketAddr) -> mpsc::Sender<Vec<u8>> {
    let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let socket = UdpSocket::bind(addr).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let mut packet = [0; MESSAGE_SIZE];
        let (_, source) = socket.recv_from(&mut packet).unwrap();
        while let Ok(packet) = write_rx.recv() {
            socket.send_to(packet.as_slice(), source).unwrap();
        }
    });
    write_tx
}

fn readwrite_benchmark(c: &mut Criterion) {
    Lazy::force(&READ_SERVER_INIT);

    // start a feedback server for read operations, that sends a response through a channel,
    // thereby skipping a proxy connection on the return.
    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let socket = UdpSocket::bind(READ_LOOP_ADDR).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let mut packet = [0; MESSAGE_SIZE];
        loop {
            let (length, _) = socket.recv_from(&mut packet).unwrap();
            let packet = &packet[..length];
            assert_eq!(packet, &DEFAULT_MESSAGE[..length]);

            if read_tx.send(packet.to_vec()).is_err() {
                return;
            }
        }
    });

    // start a feedback server for a direct write benchmark.
    let direct_write_addr = (Ipv4Addr::LOCALHOST, 9004).into();
    let direct_write_tx = write_feedback(direct_write_addr);

    // start a feedback server for a quilkin write benchmark.
    let quilkin_write_addr = (Ipv4Addr::LOCALHOST, WRITE_QUILKIN_PORT);
    let quilkin_write_tx = write_feedback(WRITE_LOOP_ADDR.parse().unwrap());
    Lazy::force(&WRITE_SERVER_INIT);

    // Sleep to give the servers some time to warm-up.
    std::thread::sleep(std::time::Duration::from_millis(150));

    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .unwrap();

    // prime the direct write connection
    socket.send_to(PACKETS[0], direct_write_addr).unwrap();

    // we need to send packets at least once a minute, otherwise the endpoint session expires.
    // So setting up a ping packet for the write test.
    // TODO(markmandel): If we ever make session timeout configurable, we can remove this.
    let ping_socket = socket.try_clone().unwrap();
    let stop = Arc::new(atomic::AtomicBool::default());
    let ping_stop = stop.clone();
    std::thread::spawn(move || {
        while !ping_stop.load(atomic::Ordering::Relaxed) {
            ping_socket.send_to(PACKETS[0], quilkin_write_addr).unwrap();
            sleep(time::Duration::from_secs(30));
        }
    });

    let mut group = c.benchmark_group("readwrite");

    for message in PACKETS {
        group.sample_size(NUMBER_OF_PACKETS);
        group.sampling_mode(criterion::SamplingMode::Flat);
        group.throughput(criterion::Throughput::Bytes(message.len() as u64));

        // direct read
        group.bench_with_input(
            BenchmarkId::new("direct-read", format!("{} bytes", message.len())),
            &message,
            |b, message| {
                b.iter(|| {
                    socket.send_to(message, READ_LOOP_ADDR).unwrap();
                    read_rx.recv().unwrap();
                })
            },
        );
        // quilkin read
        let addr = (Ipv4Addr::LOCALHOST, READ_QUILKIN_PORT);
        group.bench_with_input(
            BenchmarkId::new("quilkin-read", format!("{} bytes", message.len())),
            &message,
            |b, message| {
                b.iter(|| {
                    socket.send_to(message, addr).unwrap();
                    read_rx.recv().unwrap();
                })
            },
        );

        // direct write
        let mut packet = [0; MESSAGE_SIZE];
        group.bench_with_input(
            BenchmarkId::new("direct-write", format!("{} bytes", message.len())),
            &message,
            |b, message| {
                b.iter(|| {
                    direct_write_tx.send(message.to_vec()).unwrap();
                    socket.recv(&mut packet).unwrap();
                })
            },
        );

        // quilkin write
        let mut packet = [0; MESSAGE_SIZE];
        group.bench_with_input(
            BenchmarkId::new("quilkin-write", format!("{} bytes", message.len())),
            &message,
            |b, message| {
                b.iter(|| {
                    quilkin_write_tx.send(message.to_vec()).unwrap();
                    socket.recv(&mut packet).unwrap();
                })
            },
        );
    }

    stop.store(true, atomic::Ordering::Relaxed);
}

criterion_group!(benches, readwrite_benchmark, throughput_benchmark);
criterion_main!(benches);
