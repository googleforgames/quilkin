Quilkin provides an extensible implementation of [Filters] that allows us to plug in custom implementations to fit our needs.
This document provides an overview of the API and how we can go about writing our own [Filters].

#### API Components

The following components make up Quilkin's implementation of filters.

##### Filter

A [trait][Filter] representing an actual [Filter][built-in-filters] instance in the pipeline.

- An implementation provides a `read` and a `write` method.
- Both methods are invoked by the proxy when it consults the [filter chain] - their arguments contain information about the packet being processed.
- `read` is invoked when a packet is received on the local downstream port and is to be sent to an upstream endpoint while `write` is invoked in the opposite direction when a packet is received from an upstream endpoint and is to be sent to a downstream client.

##### FilterFactory

A [trait][FilterFactory] representing a type that knows how to create instances of a particular type of [Filter].

- An implementation provides a `name` and `create_filter` method.
- `create_filter` takes in [configuration][filter configuration] for the filter to create and returns a new instance of its filter type.
`name` returns the Filter name - a unique identifier of filters of the created type (e.g quilkin.extensions.filters.debug.v1alpha1.Debug).

##### FilterRegistry

A [struct][FilterRegistry] representing the set of all filter types known to the proxy.
It contains all known implementations of [FilterFactory], each identified by their [name][filter-factory-name].


These components come together to form the [filter chain].
- A [FilterRegistry] is populated with the [FilterFactory] for [built-in-filters] and any custom ones we provide.
- During startup, the initial list of [filter configuration] is retrieved, either from a [static config file][proxy-config] or dynamically from a [management server].
- Each [filter configuration] is used to invoke the matching (based on the Filter name) [FilterFactory] in the [FilterRegistry] - creating a [Filter] instance.
- Finally, the created [Filter] instances are piped together to form the [filter chain].

Note that when using dynamic configuration, the process repeats in a similar manner - new filter instances are created according to the updated [filter configuration] and a new [filter chain] is re-created while the old one is dropped.


##### Creating Custom Filters

To extend Quilkin's code with our own custom filter, we need to do the following:

1. Import the Quilkin crate.
1. Implement the [Filter] trait with our custom logic, as well as a [FilterFactory] that knows how to create instances of the Filter impelmentation.
1. Start the proxy with the custom [FilterFactory] implementation.

> The full source code used in this example can be found [here][example]


1. **Import the Quilkin crate**

   ```bash
   # Start with a new crate
   cargo new --bin quilkin-filter-example
   ```
   Add Quilkin as a dependency in `Cargo.toml`.
   ```toml
   [dependencies]
   quilkin = "0.1.0"
   ```
1. **Implement the filter traits**

   Its not terribly important what the filter in this example does so lets write a `Greet` filter that appends `Hello` to every packet in one direction and `Goodbye` to packets in the opposite direction.

   We start with the [Filter] implementation
   ```rust
   // src/main.rs
   use quilkin::filters::{Filter, ReadContext, ReadResponse, WriteContext, WriteResponse};

   // This creates adds an associated const named `FILTER_NAME` that points
   // to `"greet.v1"`.
   #[quilkin::filter("greet.v1")]
   struct Greet;

   impl Filter for Greet {
       fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
           ctx.contents.splice(0..0, String::from("Hello ").into_bytes());
           Some(ctx.into())
       }
       fn write(&self, mut ctx: WriteContext) -> Option<WriteResponse> {
           ctx.contents.splice(0..0, String::from("Goodbye ").into_bytes());
           Some(ctx.into())
       }
   }
   ```

   Next, we implement a [FilterFactory] for it and give it a name:

   ```rust
   // src/main.rs
   # #[quilkin::filter("greet.v1")]
   # struct Greet;
   # impl Filter for Greet {}
   # use quilkin::filters::Filter;
   use quilkin::filters::{CreateFilterArgs, Error, FilterFactory};

   struct GreetFilterFactory;
   impl FilterFactory for GreetFilterFactory {
       fn name(&self) -> &'static str {
           // We provide the name of filter that we defined with `#[quilkin::filter]`
           Greet::FILTER_NAME
       }
       fn create_filter(&self, _: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
           Ok(Box::new(Greet))
       }
   }
   ```

1. **Start the proxy**

   We can run the proxy in the exact manner as the default Quilkin binary using the [runner] module, passing in our custom [FilterFactory].
   Lets add a main function that does that. Quilkin relies on the [Tokio] async runtime so we need to import that crate and wrap our main function with it.

   Add Tokio as a dependency in `Cargo.toml`.
   ```toml
   [dependencies]
   quilkin = "0.1.0-dev"
   tokio = { version = "1", features = ["full"]}
   ```

   Add a main function that starts the proxy.
   ```no_run
   // src/main.rs
   # use quilkin::filters::{CreateFilterArgs, Filter, Error, FilterFactory};

   # struct GreetFilterFactory;
   # impl FilterFactory for GreetFilterFactory {
   #     fn name(&self) -> &'static str {
   #         "greet.v1"
   #     }
   #     fn create_filter(&self, _: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
   #         unimplemented!()
   #     }
   # }
   use quilkin::{filters::DynFilterFactory, runner::run};

   #[tokio::main]
   async fn main() {
       run(vec![Box::new(GreetFilterFactory) as DynFilterFactory]).await.unwrap();
   }
   ```

Now, let's try out the proxy. The following configuration starts our extended version of the proxy at port 7001
and forwards all packets to an upstream server at port 4321.

```yaml
# config.yaml
version: v1alpha1
proxy:
  port: 7001
static:
  filters:
  - name: greet.v1
  endpoints:
  - address: 127.0.0.1:4321
```
- Start the proxy
  ```bash
  cargo run -- -f config.yaml
  ```

- Start a UDP listening server on the configured port
  ```bash
  nc -lu 127.0.0.1 4321
  ```

- Start an interactive UDP client that sends packet to the proxy
  ```bash
  nc -u 127.0.0.1 7001
  ```

Whatever we pass to the client should now show up with our modification on the listening server's standard output.
For example typing `Quilkin` in the client prints `Hello Quilkin` on the server.

#### Working with Filter Configuration

Let's extend the `Greet` filter to require a configuration that contains what greeting to use.

The [Serde] crate is used to describe static YAML configuration in code while [Prost] to describe dynamic configuration as [Protobuf] messages when talking to the [management server].

##### Static Configuration
1. Add the yaml parsing crates to Cargo.toml:

   ```toml
      [dependencies]
      # ...
      serde = "1.0"
      serde_yaml = "0.8"
   ```

1.  Define a struct representing the config:

    ```rust
    // src/main.rs
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    struct Config {
        greeting: String,
    }
    ```

1. Update the `Greet` Filter to take in `greeting` as a parameter:

   ```rust
   // src/main.rs

   # use quilkin::filters::{Filter, ReadContext, ReadResponse, WriteContext, WriteResponse};

   #[quilkin::filter("greet.v1")]
   struct Greet(String);

   impl Filter for Greet {
       fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
           ctx.contents
               .splice(0..0, format!("{} ",self.0).into_bytes());
           Some(ctx.into())
       }
       fn write(&self, mut ctx: WriteContext) -> Option<WriteResponse> {
           ctx.contents
               .splice(0..0, format!("{} ",self.0).into_bytes());
           Some(ctx.into())
       }
   }
   ```

1. Finally, update `GreetFilterFactory` to extract the greeting from the passed in configuration and forward it onto the `Greet` Filter.

   ```rust
   // src/main.rs

   # use serde::{Deserialize, Serialize};
   # #[derive(Serialize, Deserialize, Debug)]
   # struct Config {
   #     greeting: String,
   # }
   # use quilkin::filters::{CreateFilterArgs, Error, FilterFactory, Filter, ReadContext, ReadResponse, WriteContext, WriteResponse};
   # struct Greet(String);
   # impl Filter for Greet { }

   use quilkin::filters::ConfigType;

   struct GreetFilterFactory;
   impl FilterFactory for GreetFilterFactory {
       fn name(&self) -> &'static str {
           "greet.v1"
       }
       fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
           let greeting = match args.config.unwrap() {
               ConfigType::Static(config) => {
                   serde_yaml::from_str::<Config>(serde_yaml::to_string(config).unwrap().as_str())
                    .unwrap()
                    .greeting
               }
               ConfigType::Dynamic(_) => unimplemented!("dynamic config is not yet supported for this filter"),
           };
           Ok(Box::new(Greet(greeting)))
       }
   }
   ```

And with these changes we have wired up static configuration for our filter. Try it out with the following config.yaml:
```yaml
# config.yaml
version: v1alpha1
proxy:
  port: 7001
static:
  filters:
  - name: greet.v1
    config:
      greeting: Hey
  endpoints:
  - address: 127.0.0.1:4321
```

##### Dynamic Configuration

You might have noticed while adding [static configuration support][anchor-static-config], that the [config][create-filter-args-config] argument passed into our [FilterFactory]
has a [Dynamic][config-type-dynamic] variant.
```ignore
let greeting = match args.config.unwrap() {
    ConfigType::Static(config) => {
        serde_yaml::from_str::<Config>(serde_yaml::to_string(config).unwrap().as_str())
         .unwrap()
         .greeting
    }
    ConfigType::Dynamic(_) => unimplemented!("dynamic config is not yet supported for this filter"),
};
```

It contains the serialized [Protobuf] message received from the [management server] for the [Filter] to create.
As a result, its contents are entirely opaque to Quilkin and it is represented with the [Prost Any][prost-any] type so the [FilterFactory]
can interpret its contents anyway it wishes to.
However, it usually contains a Protobuf equivalent of the filter's static configuration.

1. Add the proto parsing crates to Cargo.toml:

   ```toml
   [dependencies]
   # ...
   prost = "0.7"
   prost-types = "0.7"
   ```
1. Create a [Protobuf] equivalent of the [static configuration][anchor-static-config]:

   ```proto
   # src/greet.proto
   syntax = "proto3";
   package greet;
   message Greet {
     string greeting = 1;
   }
   ```
1. Generate Rust code from the proto file:

   There are a few ways to generate [Prost] code from proto, we will use the [prost_build] crate in this example.

   1. Add the required crates to Cargo.toml
      ```toml
      [dependencies]
      # ...
      bytes = "1.0"

      [build-dependencies]
      prost-build = "0.7"
      ```

   1. Add a [build script][build-script] to generate the Rust code during compilation:

      ```ignore
      // build.rs
      fn main() {
        prost_build::compile_protos(&["src/greet.proto"], &["src/"]).unwrap();
      }
      ```
   1. Include the generated code:

      ```ignore
      mod greet {
        include!(concat!(env!("OUT_DIR"), "/greet.rs"));
      }
      ```
    1. Decode the serialized proto message into the generated config:

       ```rust
       // src/main.rs
       # use quilkin::filters::{ConfigType, CreateFilterArgs, Error, Filter, FilterFactory};
       # use serde::{Deserialize, Serialize};
       # #[derive(Serialize, Deserialize, Debug)]
       # struct Config {
       #     greeting: String,
       # }
       # pub mod greet {
       #    #[derive(Debug,Default)]
       #    pub struct Greet{ pub greeting: String }
       #    use prost::encoding::{WireType, DecodeContext};
       #    use prost::DecodeError;
       #    use bytes::{BufMut, Buf};
       #    impl prost::Message for Greet {
       #      fn encoded_len(&self) -> usize { todo!() }
       #      fn encode_raw<B>(&self, _: &mut B) where B: BufMut { todo!() }
       #      fn merge_field<B>(&mut self, _: u32, _: WireType, _: &mut B, _: DecodeContext) -> std::result::Result<(), DecodeError> where B: Buf { todo!() }
       #      fn clear(&mut self) { todo!() }
       #    }
       # }
       # struct Greet(String);
       # impl Filter for Greet { }
       use bytes::Bytes;

       struct GreetFilterFactory;
       impl FilterFactory for GreetFilterFactory {
           fn name(&self) -> &'static str {
               "greet.v1"
           }
           fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
               let greeting = match args.config.unwrap() {
                   ConfigType::Static(config) => {
                       serde_yaml::from_str::<Config>(serde_yaml::to_string(config).unwrap().as_str())
                           .unwrap()
                           .greeting
                   }
                   ConfigType::Dynamic(config) => {
                       let config: greet::Greet = prost::Message::decode(Bytes::from(config.value)).unwrap();
                       config.greeting
                   }
               };
               Ok(Box::new(Greet(greeting)))
           }
       }
       ```

[Filter]: #
[FilterFactory]: #
[filter-factory-name]: #FilterFactory::name
[FilterRegistry]: #
[FilterChain]: #
[runner]: #
[create-filter-args-config]: #CreateFilter::config
[config-type-dynamic]: #ConfigType::Dynamic

[anchor-static-config]: #static-configuration
[Filters]: ./filters.md
[filter chain]: ./filters.md#filters-and-filter-chain
[built-in-filters]: ./filters.md#built-in-filters
[filter configuration]: ./filters.md#filter-config
[proxy-config]: ../../proxy-configuration.md
[management server]: ../../xds.md
[Tokio]: https://docs.rs/tokio/1.5.0/tokio/
[Prost]: https://docs.rs/prost/0.7.0/prost/
[Protobuf]: https://developers.google.com/protocol-buffers
[Serde]: https://docs.serde.rs/serde_yaml/index.html
[prost-any]: https://docs.rs/prost-types/0.7.0/prost_types/struct.Any.html
[prost_build]: https://docs.rs/prost-build/0.7.0/prost_build/
[build-script]: https://doc.rust-lang.org/cargo/reference/build-scripts.html
[example]: https://github.com/googleforgames/quilkin/tree/main/examples/quilkin-filter-example
