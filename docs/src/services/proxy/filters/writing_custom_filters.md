# Writing Custom Filters

> The full source code used in this example can be found
  in [`examples/`][example].

Quilkin provides an extensible implementation of [Filters] that allows us to
plug in custom implementations to fit our needs.  This document provides an
overview of the API and how we can go about writing our own [Filters]. First
we need to create a type and implement two traits for it.

It's not terribly important what the filter in this example does so let's write
a `Greet` filter that appends `Hello` to every packet in one direction and
`Goodbye` to packets in the opposite direction.

```rust,no_run,noplayground
struct Greet;
```

> As a convention within Quilkin: Filter names are singular, they also tend to
> be a verb, rather than an adjective.
>
>  **Examples**
>  - **Greet** not "Greets"
>  - **Compress** not "Compressor".

## `Filter`

Represents the actual [Filter][built-in-filters] instance in the pipeline. An
implementation provides a `read` and a `write` method (both are passthrough
by default) that accepts a context object and returns a response.

Both methods are invoked by the proxy when it consults the [filter chain]
`read` is invoked when a packet is received on the local downstream port and
is to be sent to an upstream endpoint while `write` is invoked in the opposite
direction when a packet is received from an upstream endpoint and is to be
sent to a downstream client.

```rust,no_run,noplayground
# struct Greet;
use quilkin::filters::prelude::*;

#[async_trait::async_trait]
impl Filter for Greet {
    async fn read(&self, ctx: &mut ReadContext) -> Result<(), FilterError> {
        ctx.contents.extend(b"Hello");
        Ok(())
    }
    async fn write(&self, ctx: &mut WriteContext) -> Result<(), FilterError> {
        ctx.contents.extend(b"Goodbye");
        Ok(())
    }
}
```

## `StaticFilter`

Represents metadata needed for your [`Filter`], most of it has to with defining
configuration, for now we can use `()` as we have no configuration currently.

```rust,no_run,noplayground
# use quilkin::filters::prelude::*;
# struct Greet;
# impl Filter for Greet {}
impl StaticFilter for Greet {
    const NAME: &'static str = "greet.v1";
    type Configuration = ();
    type BinaryConfiguration = ();

    fn try_from_config(config: Option<Self::Configuration>) -> Result<Self, CreationError> {
        Ok(Self)
    }
}
```

## Running

We can run the proxy using `Proxy::run` function. Let's
add a main function that does that. Quilkin relies on the [Tokio] async
runtime, so we need to import that crate and wrap our main function with it.

We can also register custom filters in quilkin using [`FilterRegistry::register`][FilterRegistry::register]

Add Tokio as a dependency in `Cargo.toml`.

```toml
[dependencies]
quilkin = "0.2.0"
tokio = { version = "1", features = ["full"]}
```

Add a main function that starts the proxy.

```rust,no_run,noplayground,ignore
// src/main.rs
{{#include ../../../../../examples/quilkin-filter-example/src/main.rs:run}}
```

Now, let's try out the proxy. The following configuration starts our extended
version of the proxy at port 7777 and forwards all packets to an upstream server
at port 4321.

```yaml
# quilkin.yaml
version: v1alpha1
filters:
  - name: greet.v1
clusters:
  default:
    localities:
        - endpoints:
            - address: 127.0.0.1:4321
```

Next we to setup our network of services, for this example we're going to use
the `netcat` tool to spawn a UDP echo server and interactive client for us to
send packets over the wire.

```bash
# Start the proxy
cargo run -- &
# Start a UDP listening server on the configured port
nc -lu 127.0.0.1 4321 &
# Start an interactive UDP client that sends packet to the proxy
nc -u 127.0.0.1 7777
```

Whatever we pass to the client should now show up with our modification on the
listening server's standard output.  For example typing `Quilkin` in the client
prints `Hello Quilkin` on the server.

## Configuration

Let's extend the `Greet` filter to have a configuration that contains what
greeting to use.

The [Serde] crate is used to describe static YAML configuration in code while
[Tonic]/[Prost] is used to describe dynamic configuration as [Protobuf] messages
when talking to a [management server].

### YAML Configuration

First let's create the type for our configuration:

1. Add the yaml parsing crates to `Cargo.toml`:

```toml
# [dependencies]
serde = "1.0"
serde_yaml = "0.8"
```

2. Define a struct representing the config:

```rust,no_run,noplayground,ignore
// src/main.rs
{{#include ../../../../../examples/quilkin-filter-example/src/main.rs:serde_config}}
```

3. Update the `Greet` Filter to take in `greeting` as a parameter:

```rust,no_run,noplayground,ignore
// src/main.rs
{{#include ../../../../../examples/quilkin-filter-example/src/main.rs:filter}}
```

### Protobuf Configuration

Quilkin comes with out-of-the-box support for xDS management, and as such needs
to communicate filter configuration over [Protobuf] with management servers and
clients to synchronise state across the network. So let's add the binary version
of our `Greet` configuration.

1. Add the proto parsing crates to `Cargo.toml`:

```toml
[dependencies]
# ...
tonic = "0.5.0"
prost = "0.7"
prost-types = "0.7"
```

2. Create a [Protobuf] equivalent of our YAML configuration.

```plaintext,no_run,noplayground,ignore
// src/greet.proto
{{#include ../../../../../examples/quilkin-filter-example/src/greet.proto:proto}}
```

3. Generate Rust code from the proto file:

There are a few ways to generate [Prost] code from proto, we will use the [prost_build] crate in this example.

Add the following required crates to `Cargo.toml`, and then add a
[build script][build-script] to generate the following Rust code
during compilation:

```toml
# [dependencies]
bytes = "1.0"

# [build-dependencies]
prost-build = "0.7"
```

```rust,no_run,noplayground,ignore
// src/build.rs
{{#include ../../../../../examples/quilkin-filter-example/build.rs:build}}
```

To include the generated code, we'll use [`tonic::include_proto`], then we just
need to implement [std::convert::TryFrom] for converting the protobuf message to
equivalvent configuration.


```rust,no_run,noplayground,ignore
// src/main.rs
{{#include ../../../../../examples/quilkin-filter-example/src/main.rs:include_proto}}

{{#include ../../../../../examples/quilkin-filter-example/src/main.rs:TryFrom}}
```

Now, let's update `Greet`'s `StaticFilter` implementation to use the two
configurations.

```rust,no_run,noplayground,ignore
// src/main.rs
{{#include ../../../../../examples/quilkin-filter-example/src/main.rs:factory}}
```

That's it! With these changes we have wired up static configuration for our
filter. Try it out with the following configuration:

```yaml
# quilkin.yaml
{{#include ../../../../../examples/quilkin-filter-example/config.yaml:yaml}}
```

[FilterInstance]: ../../../../api/quilkin/filters/prelude/struct.FilterInstance.html
[Filter]: ../../../../api/quilkin/filters/trait.Filter.html
[FilterFactory]: ../../../../api/quilkin/filters/trait.FilterFactory.html
[filter-factory-name]: ../../../../api/quilkin/filters/trait.FilterFactory.html#tymethod.name
[FilterRegistry]: ../../../../api/quilkin/filters/struct.FilterRegistry.html
[FilterRegistry::register]: ../../../../api/quilkin/filters/struct.FilterRegistry.html#method.register
[CreateFilterArgs::config]: ../../../api/quilkin/filters/prelude/struct.CreateFilterArgs.html#structfield.config
[ConfigType::dynamic]: ../../../../api/quilkin/config/enum.ConfigType.html#variant.Dynamic
[ConfigType::static]: ../../../../api/quilkin/config/enum.ConfigType.html#variant.Static
[ConfigType::deserialize]: ../../../../api/quilkin/config/enum.ConfigType.html#method.deserialize
[std::convert::TryFrom]: https://doc.rust-lang.org/std/convert/trait.TryFrom.html

[Filters]: ../filters.md
[filter chain]: ../filters.md#filters-and-filter-chain
[built-in-filters]: ../filters.md#built-in-filters
[filter configuration]: ../filters.md#filter-config
[proxy-config]: ../../deployment/configuration.md
[management server]: ../../xds.md
[tokio]: https://docs.rs/tokio
[tonic]: https://docs.rs/tonic
[prost]: https://docs.rs/prost
[Protobuf]: https://developers.google.com/protocol-buffers
[Serde]: https://docs.serde.rs/serde_yaml/index.html
[prost-any]: https://docs.rs/prost-types/0.7.0/prost_types/struct.Any.html
[prost_build]: https://docs.rs/prost-build/0.7.0/prost_build/
[build-script]: https://doc.rust-lang.org/cargo/reference/build-scripts.html
[example]: https://github.com/googleforgames/quilkin/tree/{{GITHUB_REF_NAME}}/examples/quilkin-filter-example
