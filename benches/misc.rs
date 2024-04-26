use divan::Bencher;

#[divan::bench]
fn endpoint_try_from(b: Bencher) {
    b.with_inputs(
        .bench(|| divan::black_box(serialize_to_protobuf(&gc.cm)));
}


fn main() {
    divan::main();
}
