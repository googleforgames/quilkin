# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#  __     __         _       _     _
#  \ \   / /_ _ _ __(_) __ _| |__ | | ___ ___
#   \ \ / / _` | '__| |/ _` | '_ \| |/ _ \ __|
#    \ V / (_| | |  | | (_| | |_) | |  __\__ \
#     \_/ \__,_|_|  |_|\__,_|_.__/|_|\___|___/
#

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
build_path := $(dir $(mkfile_path))
project_path := $(realpath $(build_path)/..)

CARGO_HOME ?= ~/.cargo
BUILD_IMAGE_TAG ?= quilkin-build
rust_toolchain := $(shell grep channel $(project_path)/rust-toolchain.toml | awk '{ print $$3 }')

# if this is a release, don't put the sha, otherwise, leave it off.
ifdef QUILKIN_RELEASE
	package_version := $(shell grep version -m 1 $(project_path)/Cargo.toml | awk '{print $$3}')
else
	git_sha := $(shell git rev-parse --short=7 HEAD)
	package_version := $(shell grep version -m 1 $(project_path)/Cargo.toml | awk '{print $$3}')-${git_sha}
endif

# Set this value if you want to use an external registry
REPOSITORY ?= ""
IMAGE_TAG ?= ${REPOSITORY}quilkin:$(package_version)
MINIKUBE_PROFILE ?= quilkin
CARGO_TARGET_DIR ?= /workspace/target/build-image
common_rust_args := -v $(project_path):/workspace -w /workspace \
					-v $(CARGO_HOME)/registry:/usr/local/cargo/registry \
					-e "CARGO_TARGET_DIR=$(CARGO_TARGET_DIR)"

KUBECONFIG ?= ~/.kube/config
kubeconfig_path := $(dir $(KUBECONFIG))
helm_config := ~/.config/helm
helm_cache := ~/.cache/helm

kube_mount_args := -v $(kubeconfig_path):/root/.kube -v $(helm_config):/root/.config/helm -v $(helm_cache):/root/.cache/helm
minikube_args := --network=host -v ~/.minikube:$(HOME)/.minikube
gcloud_mount_args := -v $(build_path)/.config/gcloud:/root/.config/gcloud

cargo_build_x86_64_linux := build --release --target x86_64-unknown-linux-gnu
cargo_build_x86_64_apple := build --release --target x86_64-apple-darwin
cargo_build_x86_64_windows := build --release --target x86_64-pc-windows-gnu

#   _____                    _
#  |_   _|_ _ _ __ __ _  ___| |_ ___
#    | |/ _` | '__/ _` |/ _ \ __/ __|
#    | | (_| | | | (_| |  __/ |_\__ \
#    |_|\__,_|_|  \__, |\___|\__|___/
#                 |___/

help: ensure-multi-arch
	@cat $(MAKEFILE_LIST) | docker run --rm -i xanders/make-help

ensure-multi-arch:
	@docker run --privileged --rm tonistiigi/binfmt --install linux/amd64,linux/arm64 > /dev/null 2>&1

# output the current build version
version:
	@echo $(package_version)

# Run all tests
test: ensure-build-image test-quilkin test-examples test-docs

# test only the quilkin crate
test-quilkin: ensure-build-image
	docker run --rm $(common_rust_args) \
			--entrypoint=cargo $(BUILD_IMAGE_TAG) deny check
	docker run --rm $(common_rust_args) \
		--entrypoint=cargo $(BUILD_IMAGE_TAG) clippy --tests -- -D warnings
	docker run --rm $(common_rust_args) \
		--entrypoint=cargo $(BUILD_IMAGE_TAG) fmt -- --check
	docker run --rm $(common_rust_args) \
			--entrypoint=cargo $(BUILD_IMAGE_TAG) test

# Run tests against the examples
test-examples: ensure-build-image
	docker run --rm $(common_rust_args) -w /workspace/examples/quilkin-filter-example \
		--entrypoint=cargo $(BUILD_IMAGE_TAG) clippy --tests -- -D warnings
	docker run --rm $(common_rust_args) -w /workspace/examples/quilkin-filter-example \
		--entrypoint=cargo $(BUILD_IMAGE_TAG) fmt -- --check

# Run tests against documentation
test-docs: ensure-build-image
	docker run --rm $(common_rust_args) \
		--entrypoint=bash $(BUILD_IMAGE_TAG) -c \
			'export RUSTDOCFLAGS="-Dwarnings" && mkdir /tmp/docs && \
			mkdir -p "$(CARGO_TARGET_DIR)/doc"; \
			cargo doc --workspace --no-deps && cd docs && mdbook build --dest-dir /tmp/docs/book && \
			cp -r "$(CARGO_TARGET_DIR)/doc" /tmp/docs/api && \
			rm /tmp/docs/book/print.html && \
			htmltest -c /workspace/docs/htmltest.yaml /tmp/docs'

# Build all binaries, images and related artifacts
build: binary-archive build-image

# Build all binaries
build-all-binaries: ensure-build-image build-linux-binary build-macos-binary build-windows-binary

# Build an archive all binaries
binary-archive: ensure-build-image build-all-binaries
	docker run --rm $(common_rust_args) -w $(CARGO_TARGET_DIR) \
			--entrypoint=bash $(BUILD_IMAGE_TAG) -c 'zip ../../quilkin-$(package_version).zip ./*/release/quilkin ./*/release/quilkin.exe'

# Build binary for x86_64-unknown-linux-gnu.
# Use BUILD_LOCAL=1 to build through local cargo rather than through the build container.
build-linux-binary: ensure-build-image
ifdef BUILD_LOCAL
	cargo $(cargo_build_x86_64_linux)
else
	docker run --rm $(common_rust_args) -e "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=/usr/bin/x86_64-linux-gnu-gcc" \
		--entrypoint=cargo $(BUILD_IMAGE_TAG) $(cargo_build_x86_64_linux)
endif

# Build binary for x86_64-pc-windows-gnu
# Use BUILD_LOCAL=1 to build through local cargo rather than through the build container.
build-windows-binary: ensure-build-image
ifdef BUILD_LOCAL
	cargo $(cargo_build_x86_64_windows)
else
	docker run --rm $(common_rust_args) -e "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=/usr/bin/x86_64-w64-mingw32-gcc" \
		--entrypoint=cargo $(BUILD_IMAGE_TAG) $(cargo_build_x86_64_windows)
endif

# Build binary for x86_64-apple-darwin
# Use BUILD_LOCAL=1 to build through local cargo rather than through the build container.
# Warning: May fail on arm64 hosts.
build-macos-binary: ensure-multi-arch
ifdef BUILD_LOCAL
	cargo $(cargo_build_x86_64_apple)
else
	docker run --rm -v $(project_path):/workspace -w /workspace \
		-v $(CARGO_HOME)/registry:/root/.cargo/registry \
		-e "CARGO_TARGET_DIR=$(CARGO_TARGET_DIR)" \
		-e "CC=o64-clang" -e "CXX=o64-clang++" \
		joseluisq/rust-linux-darwin-builder:$(rust_toolchain) \
			sh -c "rustup target add x86_64-apple-darwin && cargo $(cargo_build_x86_64_apple)"
endif

# Build container image.
# Use either `REPOSITORY` to specify a container repository (defaults to blank/none), or use `IMAGE_TAG` argument to specify
# the entire image name and tag. Defaults to `quilkin:${version}-${git-sha}`.
# Use BUILD_LOCAL=1 to build the binary through local cargo rather than through the build container.
build-image: ensure-build-image build-linux-binary
build-image:
	-mkdir -p "$(project_path)/target/image/"
ifdef BUILD_LOCAL
	cp "$(project_path)/target/x86_64-unknown-linux-gnu/release/quilkin" "$(project_path)/target/image/"
else
	cp "$(project_path)/target/build-image/x86_64-unknown-linux-gnu/release/quilkin" "$(project_path)/target/image/"
endif
	docker run --rm $(common_rust_args) \
		--entrypoint=bash $(BUILD_IMAGE_TAG) -c 'cargo about generate license.html.hbs > license.html'
	docker run --rm $(common_rust_args) \
		--entrypoint=bash $(BUILD_IMAGE_TAG) -c './image/archive_dependencies.sh'
	docker build --platform=linux/amd64 -t $(IMAGE_TAG) -f $(project_path)/image/Dockerfile $(project_path)

# Builds Quilkin, pushes it to a repository (use REPOSITORY arg to set value)
# and then runs the Agones integration tests. See targets `build-images` and `push` for more options and details.
# Not part of `test` as it requires a Kubernetes cluster to be provisioned and running.
# To pass extra arguments to `cargo test`, to run only a single test, for example, use the `ARGS` variable
# to set those options.
# If a `kubectl` authentication failure occurs, run `kubectl get ns` to confirm access and refresh the Kubernetes
# authentication token, and try again if successful.
test-agones: push
test-agones:
	$(MAKE) run-test-agones

run-test-agones: ensure-kube-dirs
run-test-agones:
	docker run --rm $(DOCKER_RUN_ARGS) $(common_rust_args) -w /workspace/agones  \
			--entrypoint=cargo $(BUILD_IMAGE_TAG) clippy --tests -- -D warnings
	docker run --rm $(DOCKER_RUN_ARGS) $(common_rust_args) -w /workspace/agones \
		--entrypoint=cargo $(BUILD_IMAGE_TAG) fmt -- --check
	# Confirm access to K8s, and force refresh of the auth token for the kube context
	docker run --rm $(DOCKER_RUN_ARGS) $(common_rust_args) $(kube_mount_args) -w /workspace/agones \
		--entrypoint=kubectl $(BUILD_IMAGE_TAG) get ns
	docker run --rm $(DOCKER_RUN_ARGS) $(common_rust_args) $(kube_mount_args) -w /workspace/agones \
			-e "RUST_BACKTRACE=1" -e "IMAGE_TAG=${IMAGE_TAG}" --entrypoint=cargo $(BUILD_IMAGE_TAG) test $(ARGS)

# Convenience target to build and push quilkin images to a repository.
# Use `REPOSITORY` arg to specify the repository to push to.
# USe `SKIP_BUILD_IMAGE` if you want to skip building the image if it has been already built.
# See `build-image` for more details.
push:
ifndef SKIP_BUILD_IMAGE
push: build-image
endif
	docker push $(IMAGE_TAG)

# Convenience target to build and push quilkin images into a minikube instance
# Use `MINIKUBE_PROFILE` to specify the profile. Defaults to `quilkin`.
minikube-push: build-image
	minikube image load $(IMAGE_TAG) -p $(MINIKUBE_PROFILE)

# Builds Quilkin, pushes it to a minikube instance (use `MINIKUBE_PROFILE` to specify the profile. Defaults to `quilkin`)
# and then runs the Agones integration tests. See targets `build-images` and `minikube-push` for more options and details.
# Not part of `test` as it requires a Kubernetes cluster to be provisioned and running.
# To pass extra arguments to `cargo test`, to run only a single test, for example, use the `ARGS` variable
# to set those options.
minikube-test-agones: minikube-push
	$(MAKE) DOCKER_RUN_ARGS="$(minikube_args)" run-test-agones

# Runs mdbook and cargo doc in the same directory structure as what is hosted on Github pages.
# Open http://localhost:3000/book/index.html or http://localhost:3000/api/quilkin/index.html after running. Pages will live reload on change.
# (the .html extension is required for hot reload, but pages will display without it)
docs: ensure-build-image
	@echo "📭 Open browser to http://localhost:3000/book/index.html or http://localhost:3000/api/quilkin/index.html (the .html extension is required for hot reload)"
	docker run -it --rm $(common_rust_args) -p 3000:3000 \
		--entrypoint=bash $(BUILD_IMAGE_TAG) -c \
			'mkdir /tmp/docs && (live-server -p 3000 /tmp/docs &) && \
			mkdir -p "$(CARGO_TARGET_DIR)/doc"; ln -s "$(CARGO_TARGET_DIR)/doc" /tmp/docs/api && \
			cargo watch -s "cargo doc --workspace --no-deps && cd docs && mdbook build --dest-dir /tmp/docs/book"'

# Start an interactive shell inside the build image
# Useful for testing, or adhoc cargo, gcloud, kubectl or terraform commands
shell: ensure-gcloud-dirs ensure-kube-dirs ensure-build-image
	docker run --rm -it $(DOCKER_RUN_ARGS) $(common_rust_args) \
		$(gcloud_mount_args) $(kube_mount_args) \
		 --entrypoint=bash $(BUILD_IMAGE_TAG)

ensure-build-image: ensure-cargo-registry
	docker build $(BUILD_IMAGE_ARG) --build-arg RUST_TOOLCHAIN=$(rust_toolchain) --tag=$(BUILD_IMAGE_TAG) $(build_path)/build-image/

ensure-cargo-registry:
	-mkdir -p $(CARGO_HOME)/registry

ensure-gcloud-dirs:
	-mkdir -p $(build_path)/.gcloud

ensure-kube-dirs:
	-mkdir -p ~/.config/helm
	-mkdir -p ~/.kube

ci-gcloud-auth-cluster:
	# Internal CI target. Used to authenticate against the integration test cluster.
	docker run --rm $(DOCKER_RUN_ARGS) $(common_rust_args) $(kube_mount_args) --network=cloudbuild \
		   -e "USE_GKE_GCLOUD_AUTH_PLUGIN=True" --entrypoint=gcloud $(BUILD_IMAGE_TAG) container clusters get-credentials agones --zone us-west1-c
