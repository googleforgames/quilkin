use divan::Bencher;
use quilkin::filters::token_router::{HashedTokenRouter, Router, TokenRouter};
use rand::SeedableRng;

mod shared;

#[divan::bench(types = [TokenRouter, HashedTokenRouter], args = ["single:duplicates", "single:unique", "multi:2..128:duplicates", "multi:2..128:unique"])]
fn token_router<T>(b: Bencher, token_kind: &str)
where
    T: Router + Sync,
{
    let filter = <T as Router>::new();
    let gc = shared::gen_cluster_map::<42>(token_kind.parse().unwrap());

    let mut tokens = Vec::new();

    let cm = std::sync::Arc::new(gc.cm);
    cm.build_token_maps();

    // Calculate the amount of bytes for all the tokens
    for eps in cm.iter() {
        for ep in &eps.value().endpoints {
            for tok in &ep.metadata.known.tokens {
                tokens.push(tok.clone());
            }
        }
    }

    let total_token_size: usize = tokens.iter().map(|t| t.len()).sum();
    let pool = std::sync::Arc::new(quilkin::pool::BufferPool::new(1, 1));

    let mut rand = rand::rngs::SmallRng::seed_from_u64(42);

    b.with_inputs(|| {
        use rand::seq::SliceRandom as _;
        let tok = tokens.choose(&mut rand).unwrap();

        let mut rc = quilkin::filters::ReadContext::new(
            cm.clone(),
            quilkin::net::EndpointAddress::LOCALHOST,
            pool.clone().alloc(),
        );
        rc.metadata.insert(
            quilkin::net::endpoint::metadata::Key::from_static(
                quilkin::filters::capture::CAPTURED_BYTES,
            ),
            quilkin::net::endpoint::metadata::Value::Bytes((*tok).clone().into()),
        );

        rc
    })
    .counter(divan::counter::BytesCount::new(total_token_size))
    .bench_local_values(|mut rc| {
        let _ = divan::black_box(filter.sync_read(&mut rc));
    })
}

fn main() {
    divan::main();
}
