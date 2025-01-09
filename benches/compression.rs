mod shared;

use divan::Bencher;
use quilkin::{
    collections::BufferPool,
    filters::compress::{Compressor, Mode},
};
use shared::*;
use std::sync::Arc;

fn main() {
    divan::main();
}

fn init<const N: usize>() -> ([u8; N], Arc<BufferPool>) {
    use rand::{RngCore, SeedableRng};
    let mut packet = [0u8; N];

    // Fill in the packet with random bytes rather than easily compressible data
    // as game traffic will more resemble the former than the latter
    let mut rng = rand::rngs::SmallRng::seed_from_u64(N as _);
    rng.fill_bytes(&mut packet);

    (packet, Arc::new(BufferPool::new(32, 2 * 1024)))
}

#[divan::bench_group(sample_count = 1000)]
mod decompress {
    use super::*;

    #[divan::bench(consts = PACKET_SIZES)]
    fn snappy<const N: usize>(b: Bencher) {
        let (packet, pool) = init::<N>();

        let compressor = Compressor::from(Mode::Snappy);

        b.with_inputs(|| {
            let packet = pool.clone().alloc_slice(&packet);
            compressor.encode(&packet).unwrap()
        })
        .input_counter(|buf| divan::counter::BytesCount::new(buf.len()))
        .bench_local_refs(|buf| compressor.decode(buf).unwrap())
    }

    #[divan::bench(consts = PACKET_SIZES)]
    fn lz4<const N: usize>(b: Bencher) {
        let (packet, pool) = init::<N>();

        let compressor = Compressor::from(Mode::Lz4);

        b.with_inputs(|| {
            let packet = pool.clone().alloc_slice(&packet);
            compressor.encode(&packet).unwrap()
        })
        .input_counter(|buf| divan::counter::BytesCount::new(buf.len()))
        .bench_local_refs(|buf| compressor.decode(buf).unwrap())
    }
}

#[divan::bench_group(sample_count = 1000)]
mod compress {
    use super::*;

    #[divan::bench(consts = PACKET_SIZES)]
    fn snappy<const N: usize>(b: Bencher) {
        let (packet, pool) = init::<N>();

        let compressor = Compressor::from(Mode::Snappy);

        b.with_inputs(|| pool.clone().alloc_slice(&packet))
            .input_counter(|buf| divan::counter::BytesCount::new(buf.len()))
            .bench_local_refs(|buf| compressor.encode(buf).unwrap())
    }

    #[divan::bench(consts = PACKET_SIZES)]
    fn lz4<const N: usize>(b: Bencher) {
        let (packet, pool) = init::<N>();

        let compressor = Compressor::from(Mode::Lz4);

        b.with_inputs(|| pool.clone().alloc_slice(&packet))
            .input_counter(|buf| divan::counter::BytesCount::new(buf.len()))
            .bench_local_refs(|buf| compressor.encode(buf).unwrap())
    }
}
