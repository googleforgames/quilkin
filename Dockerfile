FROM lukemathwalker/cargo-chef:latest-rust-1.61.0 AS chef
COPY rust-toolchain.toml rust-toolchain.toml
RUN rustup check
WORKDIR app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook -p quilkin --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --release --bin quilkin

# We do not need the Rust toolchain to run the binary!
FROM debian:bookworm-slim AS runtime
WORKDIR app
COPY --from=builder /app/target/release/quilkin /usr/local/bin
ENTRYPOINT ["/usr/local/bin/quilkin", "run"]
