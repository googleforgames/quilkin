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
build_image_tag := quilkin-build
rust_toolchain := $(shell grep channel $(project_path)/rust-toolchain.toml | awk '{ print $$3 }')
package_version := $(shell grep version -m 1 $(project_path)/Cargo.toml | awk '{print $$3}')

common_rust_args := -v $(project_path):/workspace -w /workspace \
					-v $(CARGO_HOME):/cargo --env CARGO_HOME=/cargo
docker_in_docker := -v /var/run/docker.sock:/var/run/docker.sock

#   _____                    _
#  |_   _|_ _ _ __ __ _  ___| |_ ___
#    | |/ _` | '__/ _` |/ _ \ __/ __|
#    | | (_| | | | (_| |  __/ |_\__ \
#    |_|\__,_|_|  \__, |\___|\__|___/
#                 |___/

help:
	@cat $(MAKEFILE_LIST) | docker run --rm -i xanders/make-help

# Run all tests
test: ensure-build-image
	docker run --rm $(common_rust_args) \
 		--entrypoint=cargo $(build_image_tag) clippy --tests -- -D warnings
	docker run --rm $(common_rust_args) \
 		--entrypoint=cargo $(build_image_tag) fmt -- --check
	docker run --rm $(common_rust_args) \
     		--entrypoint=cargo $(build_image_tag) test --tests
	docker run --rm $(common_rust_args) \
     		--entrypoint=cargo $(build_image_tag) +nightly test --doc

# Build all binaries and images
build: ensure-build-image build-linux-binary build-windows-binary build-macos-binary build-image

# Build release and debug binaries for x86_64-unknown-linux-gnu
build-linux-binary: ensure-build-image
	docker run --rm $(common_rust_args) $(docker_in_docker) \
 		--entrypoint=cross $(build_image_tag) build --target x86_64-unknown-linux-gnu
	docker run --rm $(common_rust_args) $(docker_in_docker) \
 		--entrypoint=cross $(build_image_tag) build --target x86_64-unknown-linux-gnu --release

# Build release and debug binaries for x86_64-pc-windows-gnu
build-windows-binary: ensure-build-image
	docker run --rm $(common_rust_args) $(docker_in_docker) \
 		--entrypoint=cross $(build_image_tag) build --target x86_64-pc-windows-gnu
	docker run --rm $(common_rust_args) $(docker_in_docker) \
 		--entrypoint=cross $(build_image_tag) build --target x86_64-pc-windows-gnu --release

# Build release and debug binaries for x86_64-apple-darwin
build-macos-binary:
	docker run --rm -v $(project_path):/workspace -w /workspace \
		-v $(CARGO_HOME)/registry:/root/.cargo/registry \
        joseluisq/rust-linux-darwin-builder:$(rust_toolchain) \
        	sh -c "cargo build --target x86_64-apple-darwin && cargo build --release --target x86_64-apple-darwin"

# Build release and debug container images.
# Use IMAGE_NAME argument to specify the container registry and image name. Defaults to 'quilkin'.
build-image: ensure-build-image build-linux-binary
build-image: IMAGE_NAME ?= quilkin
build-image:
	docker run --rm $(common_rust_args) \
		--entrypoint=bash $(build_image_tag) -c 'cargo about generate license.html.hbs > license.html'
	docker run --rm $(common_rust_args) \
		--entrypoint=bash $(build_image_tag) -c './image/archive_dependencies.sh'
	docker build -t $(IMAGE_NAME):$(package_version)-debug --build-arg PROFILE=debug -f $(project_path)/image/Dockerfile $(project_path)
	docker build -t $(IMAGE_NAME):$(package_version) --build-arg PROFILE=release -f $(project_path)/image/Dockerfile $(project_path)

ensure-build-image:
	docker build --build-arg RUST_TOOLCHAIN=$(rust_toolchain) --tag=$(build_image_tag) $(build_path)/build-image/
