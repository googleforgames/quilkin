mod shared;

use divan::Bencher;
use shared::*;

use std::thread::spawn;

fn main() {
    divan::main();
}

/// We use this to run each benchmark on the different packets, note the size
/// of the packet rather than than packet index is used to give better output
/// from divan
const SIZES: &[usize] = &[254, 508, 1500];

#[inline]
fn counter(psize: usize) -> impl divan::counter::Counter {
    divan::counter::BytesCount::new(psize * NUMBER_OF_PACKETS)
}

#[inline]
fn get_packet_from_size<const N: usize>() -> &'static [u8] {
    PACKETS
        .iter()
        .find(|p| p.len() == N)
        .expect("failed to find appropriately sized packet")
}

mod read {
    use super::*;

    #[divan::bench(consts = SIZES)]
    fn direct<const N: usize>(b: Bencher) {
        let (writer, reader) = socket_pair(None, None);
        let (tx, rx) = channel();
        let packet = get_packet_from_size::<N>();

        let writer = Writer::new(writer, reader.local_addr().unwrap(), rx, packet);

        spawn(move || loop {
            if !writer.write_all(NUMBER_OF_PACKETS) {
                break;
            }
        });

        b.counter(counter(N)).bench_local(|| {
            read_to_end(&reader, &tx, NUMBER_OF_PACKETS, N);
        });
    }

    #[divan::bench(consts = SIZES)]
    fn quilkin<const N: usize>(b: Bencher) {
        let (writer, reader) = socket_pair(None, None);
        let (tx, rx) = channel();
        let packet = get_packet_from_size::<N>();

        //quilkin::test::enable_log("quilkin=debug");

        let _quilkin_loop = QuilkinLoop::spinup(READ_QUILKIN_PORT, reader.local_addr().unwrap());

        let writer = Writer::new(
            writer,
            (Ipv4Addr::LOCALHOST, READ_QUILKIN_PORT).into(),
            rx,
            packet,
        );

        std::thread::sleep(std::time::Duration::from_millis(100));

        spawn(move || loop {
            if !writer.write_all(NUMBER_OF_PACKETS) {
                break;
            }
        });

        b.counter(counter(N)).bench_local(|| {
            read_to_end(&reader, &tx, NUMBER_OF_PACKETS, N);
        });
    }
}

mod write {
    use super::*;

    #[divan::bench(consts = SIZES)]
    fn direct<const N: usize>(b: Bencher) {
        let (writer, reader) = socket_pair(None, None);
        let (tx, rx) = channel();
        let packet = get_packet_from_size::<N>();

        let writer = Writer::new(writer, reader.local_addr().unwrap(), rx, packet);

        let (loop_tx, loop_rx) = mpsc::sync_channel(1);

        spawn(move || {
            while let Ok((num, size)) = loop_rx.recv() {
                read_to_end(&reader, &tx, num, size);
            }
        });

        b.counter(counter(N)).bench_local(|| {
            // Signal the read loop to run
            loop_tx.send((NUMBER_OF_PACKETS, N)).unwrap();

            writer.write_all(NUMBER_OF_PACKETS);
        });
    }

    #[divan::bench(consts = SIZES)]
    fn quilkin<const N: usize>(b: Bencher) {
        let (writer, reader) = socket_pair(None, None);
        let (tx, rx) = channel();
        let packet = get_packet_from_size::<N>();

        let (loop_tx, loop_rx) = mpsc::sync_channel(1);

        let _quilkin_loop = QuilkinLoop::spinup(WRITE_QUILKIN_PORT, reader.local_addr().unwrap());

        let writer = Writer::new(
            writer,
            (Ipv4Addr::LOCALHOST, WRITE_QUILKIN_PORT).into(),
            rx,
            packet,
        );

        std::thread::sleep(std::time::Duration::from_millis(100));

        spawn(move || {
            while let Ok((num, size)) = loop_rx.recv() {
                read_to_end(&reader, &tx, num, size);
            }
        });

        b.counter(counter(N)).bench_local(|| {
            // Signal the read loop to run
            loop_tx.send((NUMBER_OF_PACKETS, N)).unwrap();

            writer.write_all(NUMBER_OF_PACKETS);
        });
    }
}
