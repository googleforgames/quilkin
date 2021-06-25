# Quilkin Development

We welcome development from the community on Quilkin!

## Cloning the repository

We use several submodules, so make sure you have them downloaded and updated.

```shell script
git clone https://github.com/googleforgames/quilkin.git
cd quilkin
git submodule update --init --recursive
```

You will likely want to replace `https://github.com/googleforgames/quilkin.git` with your own fork of the repository
for your development.

### Developing with Rust tooling

Standard development with [cargo](https://doc.rust-lang.org/cargo/) is fully supported.

#### Rust version

We target a specific version of Rust for each build, so we can be deliberate when changing versions to
track if there are any performance changes between Rust releases.

Run `rustup show` in the root of the project directory to install the rust toolchain that is standard for Quilkin
development.

#### Building

To build a debug release, run:

`cargo build`

To build a production release, run:

`cargo build --release`

#### Testing

We use some nightly features to automatically test our external documentation, so you will need to be explicit about
which tests you wish to run.

To run the unit and integration tests:

`cargo test --tests`

To run our external documentation tests:

`cargo +nightly test --doc`

### Developing with Make + Docker 

There are a few reasons you may want to use the [Make](https://www.gnu.org/software/make/)
and [Docker](https://docs.docker.com/) setup in conjunction with the Rust tooling setup:

* Run all the tests that are run in our continuous integration suite.
* Build binaries for your development version of Quilkin for all operating systems supported.
* Build a container image for your development version of Quilkin.

To use the tooling for Make + Docker testing and development, you will need:

* A *nix shell/environment, such as found on Linux, macOS or WSL on Windows.
* Make installed
* [Docker installed](https://docs.docker.com/get-docker/)

#### Run tests

`make test` will run all tests for this project.

This can be useful if continuous integration is failing, but you are unable to reproduce the issue using 
your local Rust tooling

#### Build everything

To build all operating system binaries, as well as the container image for your current development version of 
Quilkin, run `make build`.

#### Show all commands

There are more targets available than just the above.

To see all commands that are available, run `make` or `make help` from this directory.

This will display an output similar to this one with all make targets with descriptions of what they do:

```shell
$ cd build
$ make

Usage: make <command> [ARGUMENT1=value1] [ARGUMENT2=value2]

Commands:

 test                 # Run all tests

 build                # Build all binaries and images

 build-linux-binary   # Build release and debug binaries for x86_64-pc-windows-gnu

 build-windows-binary # Build release and debug binaries for x86_64-unknown-linux-gnu

 build-image          # Build release and debug container images.
                      # Use IMAGE_NAME argument to specify the container registry and image name. Defaults to 'quilkin'.
```
