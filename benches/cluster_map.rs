use std::{
    collections::BTreeSet,
    hash::{Hash as _, Hasher as _},
    net::{Ipv4Addr, Ipv6Addr},
};

use divan::Bencher;
use quilkin::net::{cluster::ClusterMap, endpoint::Locality, Endpoint, EndpointAddress};
use rand::Rng;
use xxhash_rust::xxh3::Xxh3 as Hasher;

const LOCALITIES: &[&str] = &[
    "us:east1:b",
    "us:east1:c",
    "us:east1:d",
    "us:east4:c",
    "us:east4:b",
    "us:east4:a",
    "us:central1:c",
    "us:central1:a",
    "us:central1:f",
    "us:central1:b",
    "us:west1:b",
    "us:west1:c",
    "us:west1:a",
    "europe:west4:a",
    "europe:west4:b",
    "europe:west4:c",
    "europe:west1:b",
    "europe:west1:d",
    "europe:west1:c",
    "europe:west3:c",
    "europe:west3:a",
    "europe:west3:b",
    "europe:west2:c",
    "europe:west2:b",
    "europe:west2:a",
    "asia:east1:b",
    "asia:east1:a",
    "asia:east1:c",
    "asia:southeast1:b",
    "asia:southeast1:a",
    "asia:southeast1:c",
    "asia:northeast1:b",
    "asia:northeast1:c",
    "asia:northeast1:a",
    "asia:south1:c",
    "asia:south1:b",
    "asia:south1:a",
    "australia:southeast1:b",
    "australia:southeast1:c",
    "australia:southeast1:a",
    "southamerica:east1:b",
    "southamerica:east1:c",
    "southamerica:east1:a",
    "asia:east2:a",
    "asia:east2:b",
    "asia:east2:c",
    "asia:northeast2:a",
    "asia:northeast2:b",
    "asia:northeast2:c",
    "asia:northeast3:a",
    "asia:northeast3:b",
    "asia:northeast3:c",
    "asia:south2:a",
    "asia:south2:b",
    "asia:south2:c",
    "asia:southeast2:a",
    "asia:southeast2:b",
    "asia:southeast2:c",
    "australia:southeast2:a",
    "australia:southeast2:b",
    "australia:southeast2:c",
    "europe:central2:a",
    "europe:central2:b",
    "europe:central2:c",
    "europe:north1:a",
    "europe:north1:b",
    "europe:north1:c",
    "europe:southwest1:a",
    "europe:southwest1:b",
    "europe:southwest1:c",
    "europe:west10:a",
    "europe:west10:b",
    "europe:west10:c",
    "europe:west12:a",
    "europe:west12:b",
    "europe:west12:c",
    "europe:west6:a",
    "europe:west6:b",
    "europe:west6:c",
    "europe:west8:a",
    "europe:west8:b",
    "europe:west8:c",
    "europe:west9:a",
    "europe:west9:b",
    "europe:west9:c",
    "me:central1:a",
    "me:central1:b",
    "me:central1:c",
    "me:central2:a",
    "me:central2:b",
    "me:central2:c",
    "me:west1:a",
    "me:west1:b",
    "me:west1:c",
    "northamerica:northeast1:a",
    "northamerica:northeast1:b",
    "northamerica:northeast1:c",
    "northamerica:northeast2:a",
    "northamerica:northeast2:b",
    "northamerica:northeast2:c",
    "southamerica:west1:a",
    "southamerica:west1:b",
    "southamerica:west1:c",
    "us:east5:a",
    "us:east5:b",
    "us:east5:c",
    "us:south1:a",
    "us:south1:b",
    "us:south1:c",
    "us:west2:a",
    "us:west2:b",
    "us:west2:c",
    "us:west3:a",
    "us:west3:b",
    "us:west3:c",
    "us:west4:a",
    "us:west4:b",
    "us:west4:c",
];

fn gen_endpoints(rng: &mut rand::rngs::SmallRng, hasher: &mut Hasher) -> BTreeSet<Endpoint> {
    let num_endpoints = rng.gen_range(100..10_000);
    hasher.write_u16(num_endpoints);

    let mut endpoints = BTreeSet::new();

    for i in 0..num_endpoints {
        let ep_addr = match i % 3 {
            0 => (Ipv4Addr::new(100, 200, (i >> 8) as _, (i & 0xff) as _), i).into(),
            1 => EndpointAddress {
                host: quilkin::net::endpoint::AddressKind::Name(format!("benchmark-{i}")),
                port: i,
            },
            2 => (Ipv6Addr::new(100, 200, i, 0, 0, 1, 2, 3), i).into(),
            _ => unreachable!(),
        };

        endpoints.insert(Endpoint::new(ep_addr));
    }

    for ep in &endpoints {
        ep.address.hash(hasher);
    }

    endpoints
}

#[allow(dead_code)]
struct GenCluster {
    cm: ClusterMap,
    hash: u64,
    total_endpoints: usize,
    sets: std::collections::BTreeMap<Option<Locality>, BTreeSet<Endpoint>>,
}

#[inline]
fn write_locality(hasher: &mut Hasher, loc: &Option<Locality>) {
    if let Some(key) = loc {
        key.hash(hasher);
    } else {
        hasher.write("None".as_bytes());
    }
}

fn gen_cluster_map<const S: u64>() -> GenCluster {
    use rand::prelude::*;

    let mut rng = rand::rngs::SmallRng::seed_from_u64(S);

    let mut hasher = Hasher::with_seed(S);
    let mut total_endpoints = 0;

    let num_locals = rng.gen_range(10..LOCALITIES.len());

    // Select how many localities we want, note we add 1 since we always have a default cluster
    hasher.write_usize(num_locals + 1);

    let cm = ClusterMap::default();

    for locality in LOCALITIES.choose_multiple(&mut rng, num_locals) {
        let locality = locality.parse().unwrap();
        cm.insert(Some(locality), Default::default());
    }

    // Now actually insert the endpoints, now that the order of keys is established,
    // annoying, but note we split out iteration versus insertion, otherwise we deadlock
    let keys: Vec<_> = cm.iter().map(|kv| kv.key().clone()).collect();
    let mut sets = std::collections::BTreeMap::new();

    for key in keys {
        write_locality(&mut hasher, &key);

        let ep = gen_endpoints(&mut rng, &mut hasher);
        total_endpoints += ep.len();
        cm.insert(key.clone(), ep.clone());
        sets.insert(key, ep);
    }

    GenCluster {
        cm,
        hash: hasher.finish(),
        total_endpoints,
        sets,
    }
}

#[divan::bench_group(sample_count = 10)]
mod serde {
    use super::*;
    use prost_types::Any;
    use quilkin::net::cluster::proto::Cluster;

    fn serialize_to_protobuf(cm: &ClusterMap) -> Vec<Any> {
        let mut resources = Vec::new();
        let resource_type = quilkin::net::xds::ResourceType::Cluster;

        for cluster in cm.iter() {
            resources.push(
                resource_type
                    .encode_to_any(&Cluster {
                        locality: cluster.key().clone().map(|l| l.try_into().unwrap()),
                        endpoints: cluster
                            .endpoints
                            .iter()
                            .map(TryFrom::try_from)
                            .collect::<Result<_, _>>()
                            .unwrap(),
                    })
                    .unwrap(),
            );
        }

        resources
    }

    fn deserialize_from_protobuf(pv: Vec<Any>) -> ClusterMap {
        let cm = ClusterMap::default();

        for any in pv {
            let c = quilkin::net::xds::Resource::try_from(any).unwrap();

            let quilkin::net::xds::Resource::Cluster(cluster) = c else {
                unreachable!()
            };
            cm.insert(
                cluster.locality.map(From::from),
                cluster
                    .endpoints
                    .into_iter()
                    .map(TryFrom::try_from)
                    .collect::<Result<_, _>>()
                    .unwrap(),
            );
        }

        cm
    }

    fn serialize_to_json(cm: &ClusterMap) -> serde_json::Value {
        serde_json::to_value(cm).unwrap()
    }

    fn deserialize_from_json(json: serde_json::Value) -> ClusterMap {
        serde_json::from_value(json.clone()).unwrap()
    }

    #[divan::bench(consts = SEEDS)]
    fn serialize_proto<const S: u64>(b: Bencher) {
        let gc = gen_cluster_map::<S>();
        b.counter(gc.total_endpoints)
            .bench(|| divan::black_box(serialize_to_protobuf(&gc.cm)));
    }

    #[divan::bench(consts = SEEDS)]
    fn serialize_json<const S: u64>(b: Bencher) {
        let gc = gen_cluster_map::<S>();
        b.counter(gc.total_endpoints)
            .bench(|| divan::black_box(serialize_to_json(&gc.cm)));
    }

    #[divan::bench(consts = SEEDS)]
    fn deserialize_json<const S: u64>(b: Bencher) {
        let gc = gen_cluster_map::<S>();
        let json = serialize_to_json(&gc.cm);

        b.with_inputs(|| json.clone())
            .counter(gc.total_endpoints)
            .bench_values(|json| divan::black_box(deserialize_from_json(json)));
    }

    #[divan::bench(consts = SEEDS)]
    fn deserialize_proto<const S: u64>(b: Bencher) {
        let gc = gen_cluster_map::<S>();
        let pv = serialize_to_protobuf(&gc.cm);

        b.with_inputs(|| pv.clone())
            .counter(gc.total_endpoints)
            .bench_values(|pv| divan::black_box(deserialize_from_protobuf(pv)));
    }
}

const SEEDS: &[u64] = &[100, 200, 300, 400, 500];

#[divan::bench_group(sample_count = 10)]
mod ops {
    use super::*;

    fn compute_hash<const S: u64>(gc: &GenCluster) -> usize {
        let mut total_endpoints = 0;

        for kv in gc.cm.iter() {
            total_endpoints += kv.endpoints.len();
        }

        assert_eq!(total_endpoints, gc.total_endpoints);
        total_endpoints
    }

    // #[allow(clippy::eq_op)]
    // fn is_equal(gc: &GenCluster) -> usize {
    //     assert_eq!(gc.cm, gc.cm);
    //     gc.total_endpoints
    // }

    #[divan::bench(consts = SEEDS)]
    fn iterate<const S: u64>(b: Bencher) {
        let cm = gen_cluster_map::<S>();

        b.counter(cm.total_endpoints)
            .bench_local(|| divan::black_box(compute_hash::<S>(&cm)));

        drop(cm);
    }

    #[divan::bench(consts = SEEDS)]
    fn iterate_par<const S: u64>(b: Bencher) {
        let cm = gen_cluster_map::<S>();

        b.counter(cm.total_endpoints)
            .bench(|| divan::black_box(compute_hash::<S>(&cm)))
    }

    // #[divan::bench(consts = SEEDS)]
    // fn partial_eq<const S: u64>(b: Bencher) {
    //     let cm = gen_cluster_map::<S>();

    //     b.counter(cm.total_endpoints)
    //         .bench(|| divan::black_box(is_equal(&cm)))
    // }
}

fn main() {
    divan::main();
}
