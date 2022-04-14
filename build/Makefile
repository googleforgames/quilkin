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
BUILD_IMAGE_TAG := quilkin-build
rust_toolchain := $(shell grep channel $(project_path)/rust-toolchain.toml | awk '{ print $$3 }')
package_version := $(shell grep version -m 1 $(project_path)/Cargo.toml | awk '{print $$3}')

common_rust_args := -v $(project_path):/workspace -w /workspace \
					-v $(CARGO_HOME)/registry:/usr/local/cargo/registry
docker_in_docker := -v /var/run/docker.sock:/var/run/docker.sock

#   _____                    _
#  |_   _|_ _ _ __ __ _  ___| |_ ___
#    | |/ _` | '__/ _` |/ _ \ __/ __|
#    | | (_| | | | (_| |  __/ |_\__ \
#    |_|\__,_|_|  \__, |\___|\__|___/
#                 |___/

help:
	@cat $(MAKEFILE_LIST) | docker run --rm -i xanders/make-help

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
			mkdir -p ./target/doc; \
			cargo doc --workspace --no-deps && cd docs && mdbook build --dest-dir /tmp/docs/book && \
			cp -r /workspace/target/doc /tmp/docs/api && \
			rm /tmp/docs/book/print.html && \
			htmltest -c /workspace/docs/htmltest.yaml /tmp/docs'

# Build all binaries, images and related artifacts
build: binary-archive build-image

# Build all debug and release binaries
build-all-binaries: ensure-build-image build-linux-binary build-windows-binary build-macos-binary

# Build an archive all debug and release binaries
binary-archive: ensure-build-image build-all-binaries
	docker run --rm $(common_rust_args) \
    		--entrypoint=bash $(BUILD_IMAGE_TAG) -c 'zip quilkin-$(package_version).zip ./target/*/*/quilkin ./target/*/*/quilkin.exe'

# Build release and debug binaries for x86_64-unknown-linux-gnu
build-linux-binary: ensure-build-image
	docker run --rm $(common_rust_args) $(docker_in_docker) \
 		--entrypoint=cross $(BUILD_IMAGE_TAG) build --target x86_64-unknown-linux-gnu
	docker run --rm $(common_rust_args) $(docker_in_docker) \
 		--entrypoint=cross $(BUILD_IMAGE_TAG) build --target x86_64-unknown-linux-gnu --release

# Build release and debug binaries for x86_64-pc-windows-gnu
build-windows-binary: ensure-build-image
	docker run --rm $(common_rust_args) $(docker_in_docker) \
 		--entrypoint=cross $(BUILD_IMAGE_TAG) build --target x86_64-pc-windows-gnu
	docker run --rm $(common_rust_args) $(docker_in_docker) \
 		--entrypoint=cross $(BUILD_IMAGE_TAG) build --target x86_64-pc-windows-gnu --release

# Build release and debug binaries for x86_64-apple-darwin
build-macos-binary:
	docker run --rm -v $(project_path):/workspace -w /workspace \
		-v $(CARGO_HOME)/registry:/root/.cargo/registry \
		-e "CC=o64-clang" -e "CXX=o64-clang++" \
        joseluisq/rust-linux-darwin-builder:$(rust_toolchain) \
        	sh -c "rustup target add x86_64-apple-darwin && cargo build --target x86_64-apple-darwin && cargo build --release --target x86_64-apple-darwin"

# Build release and debug container images.
# Use IMAGE_NAME argument to specify the container registry and image name. Defaults to 'quilkin'.
build-image: ensure-build-image build-linux-binary
build-image: IMAGE_NAME := quilkin
build-image:
	docker run --rm $(common_rust_args) \
		--entrypoint=bash $(BUILD_IMAGE_TAG) -c 'cargo about generate license.html.hbs > license.html'
	docker run --rm $(common_rust_args) \
		--entrypoint=bash $(BUILD_IMAGE_TAG) -c './image/archive_dependencies.sh'
	docker build -t $(IMAGE_NAME):$(package_version)-debug --build-arg PROFILE=debug -f $(project_path)/image/Dockerfile $(project_path)
	docker build -t $(IMAGE_NAME):$(package_version) --build-arg PROFILE=release -f $(project_path)/image/Dockerfile $(project_path)

# Runs mdbook and cargo doc in the same directory structure as what is hosted on Github pages.
# Open http://localhost:3000/book/index.html or http://localhost:3000/api/quilkin/index.html after running. Pages will live reload on change.
# (the .html extension is required for hot reload, but pages will display without it)
docs: ensure-build-image
	@echo "📭 Open browser to http://localhost:3000/book/index.html or http://localhost:3000/api/quilkin/index.html (the .html extension is required for hot reload)"
	docker run -it --rm $(common_rust_args) -p 3000:3000 \
		--entrypoint=bash $(BUILD_IMAGE_TAG) -c \
		 	'mkdir /tmp/docs && (live-server -p 3000 /tmp/docs &) && \
			mkdir -p ./target/doc; ln -s $$(pwd)/target/doc /tmp/docs/api && \
			cargo watch -s "cargo doc --workspace --no-deps && cd docs && mdbook build --dest-dir /tmp/docs/book"'

# Start an interactive shell inside the build image
# Useful for testing, or adhoc cargo commands
shell: ensure-build-image
	docker run --rm -it $(common_rust_args) \
		--entrypoint=bash $(BUILD_IMAGE_TAG)

ensure-build-image: ensure-cargo-registry
	docker build $(BUILD_IMAGE_ARG) --build-arg RUST_TOOLCHAIN=$(rust_toolchain) --tag=$(BUILD_IMAGE_TAG) $(build_path)/build-image/

ensure-cargo-registry:
	-mkdir -p $(CARGO_HOME)/registry
