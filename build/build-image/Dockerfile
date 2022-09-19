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

# Install packages
RUN set -eux && \
    apt-get update && \
    apt-get install -y jq wget zip build-essential libssl-dev pkg-config python3-pip bash-completion g++-mingw-w64-x86-64 && \
    pip3 install live-server && \
    echo "source /etc/bash_completion" >> /root/.bashrc

# install gcloud
# Credit: https://cloud.google.com/sdk/docs/install#deb
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg  add - && apt-get update -y && \
    apt-get install google-cloud-cli google-cloud-cli-gke-gcloud-auth-plugin kubectl -y && \
    echo "source /usr/share/google-cloud-sdk/completion.bash.inc" >> /root/.bashrc && \
    echo "source <(kubectl completion bash)" >> /root/.bashrc

# install tarrafrm
# Credit: https://learn.hashicorp.com/tutorials/terraform/install-cli
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add - && \
    apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main" && \
    apt-get update -y && apt-get install terraform -y && \
    terraform -install-autocomplete

# install helm
# Credit: https://helm.sh/docs/intro/install/
RUN curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash && \
    echo "source <(helm completion bash)" >> /root/.bashrc

# Install htmltest
WORKDIR /tmp
RUN wget --quiet -O htmltest.tar.gz https://github.com/wjdp/htmltest/releases/download/v0.16.0/htmltest_0.16.0_linux_amd64.tar.gz && \
     tar -xf htmltest.tar.gz && mv ./htmltest /usr/local/bin/ && rm htmltest.tar.gz

# Install Rust
RUN wget --quiet https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init && \
    chmod +x rustup-init && \
    ./rustup-init -y --no-modify-path --default-toolchain $RUST_TOOLCHAIN && \
    rm rustup-init && \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME && \
    rustup component add rustfmt clippy && \
    rustup target add x86_64-pc-windows-gnu && \
    cargo install cargo-watch mdbook && \
    cargo install cargo-about && \
    cargo install --locked cargo-deny && \
    rustup --version && \
    cargo --version && \
    rustc --version
