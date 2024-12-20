#!/bin/bash

# Builds the eBPF program that can be loaded by the kernel. Pass `--update` to
# update the binary embedded in quilkin

set -e

ROOT=$(git rev-parse --show-toplevel)
EBPF_ROOT="$ROOT/crates/ebpf"

cargo +nightly build -Z build-std=core --release --target bpfel-unknown-none --manifest-path "$EBPF_ROOT/Cargo.toml"

if [[ $1 == '--update' ]]; then
    cp "$EBPF_ROOT/target/bpfel-unknown-none/release/packet-router" "$ROOT/crates/xdp/bin/packet-router.bin"
fi
