# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License") &&
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM gcr.io/cloud-builders/docker

ARG RUST_TOOLCHAIN

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    CROSS_DOCKER_IN_DOCKER=true \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8

RUN set -eux && \
    apt-get update && \
    apt-get install -y wget zip build-essential libssl-dev pkg-config python3-pip && \
    pip3 install live-server && \
    wget https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init && \
    chmod +x rustup-init && \
    ./rustup-init -y --no-modify-path --default-toolchain $RUST_TOOLCHAIN && \
    rm rustup-init && \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME && \
    rustup component add rustfmt clippy && \
    cargo install cross cargo-watch mdbook && \
    cargo install cargo-about && \
    cargo install --locked cargo-deny && \
    rustup --version && \
    cargo --version && \
    rustc --version && \
    cross --version
