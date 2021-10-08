use std::net::UdpSocket;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use once_cell::sync::Lazy;

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

static SERVER_INIT: Lazy<()> = Lazy::new(|| {
    std::thread::spawn(|| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let config = quilkin::config::Builder::empty()
            .with_port(8000)
            .with_static(
                vec![],
                vec![quilkin::endpoint::Endpoint::new(
                    FEEDBACK_LOOP_ADDR.parse().unwrap(),
                )],
            )
            .build();
        let server = quilkin::Builder::from(std::sync::Arc::new(config))
            .validate()
            .unwrap()
            .build();

        runtime.block_on(async move {
            let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel::<()>(());
            server.run(shutdown_rx).await.unwrap();
        });
    });
});

static FEEDBACK_LOOP: Lazy<()> = Lazy::new(|| {
    std::thread::spawn(|| {
        let socket = UdpSocket::bind(FEEDBACK_LOOP_ADDR).unwrap();

        loop {
            let mut packet = [0; MESSAGE_SIZE];
            let (_, addr) = socket.recv_from(&mut packet).unwrap();
            let length = packet
                .iter()
                .position(|&x| x == 0)
                .unwrap_or_else(|| packet.len());
            let packet = &packet[..length];
            assert_eq!(packet, &DEFAULT_MESSAGE[..length]);
            socket.send_to(packet, addr).unwrap();
        }
    });
});

fn criterion_benchmark(c: &mut Criterion) {
    Lazy::force(&FEEDBACK_LOOP);
    Lazy::force(&SERVER_INIT);
    // Sleep to give the servers some time to warm-up.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let socket = UdpSocket::bind(BENCH_LOOP_ADDR).unwrap();
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

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
