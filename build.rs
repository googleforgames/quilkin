// Use tonic to generate the rust files we need from the protobuf files.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: emit cargo:rerun-if any of the proto deps change.
    let proto_files = vec![
        "proto/data-plane-api/envoy/config/cluster/v3/cluster.proto",
        "proto/data-plane-api/envoy/service/cluster/v3/cds.proto",
        "proto/data-plane-api/envoy/service/discovery/v3/ads.proto",
        "proto/data-plane-api/envoy/service/discovery/v3/discovery.proto",
        "proto/udpa/udpa/core/v1/resource_name.proto",
    ]
    .iter()
    .map(|name| std::env::current_dir().unwrap().join(name))
    .collect::<Vec<_>>();

    let include_dirs = vec![
        "proto/data-plane-api",
        "proto/udpa",
        "proto/googleapis",
        "proto/protoc-gen-validate",
    ]
    .iter()
    .map(|i| std::env::current_dir().unwrap().join(i))
    .collect::<Vec<_>>();

    tonic_build::configure().build_server(false).compile(
        &(proto_files
            .iter()
            .map(|path| path.to_str().unwrap())
            .collect::<Vec<_>>()),
        &include_dirs
            .iter()
            .map(|p| p.to_str().unwrap())
            .collect::<Vec<_>>(),
    )?;

    Ok(())
}
