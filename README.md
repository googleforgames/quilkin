# Quilkin

Quilkin is a non-transparent UDP proxy specifically designed for use with large scale multiplayer dedicated game servers
deployments, to ensure security, access control, telemetry data, metrics and more.
 
It is designed to be used behind game clients as well as in front of dedicated game servers.

## Planned Roadmap

- [x] Client Proxy: Configuration with a connection token
- [x] Server Proxy: Configuration of endpoints with multiple connection token attached, that provide routing 
- [x] Basic non-transparent UDP forwarding from Client Proxy to Server Proxy
- [x] Basic non-transparent UDP forwarding from Server Proxy to all Endpoints
- [ ] UDP Filtering design and implementation
- [ ] Simple UDP routing Filter (Client and Server Proxy implementation)
- [ ] gRPC configuration management control plane API
- [x] Metrics tracking and export

## Project State

Project is currently in *alpha* status, and is being actively developed. Expect things to break.

Not to be used in production systems.

## Proposed Architecture
```
                                       +                          +
                                       +                          |
                                    Internet                   Private
                                       +                       Network
                                       |     +----------------+   +          +----------------+
                                       |     | Quilkin        |   |          | Dedicated      |
                                       |  +--> (Server Proxy) +-------+------> Game Server    |
+---------+      +----------------+    |  |  |                |   |   |      |                |
|  Game   |      | Quilkin        +-------+  +----------------+   |   |      +----------------+
|  Client +------+ (Client Proxy) |    |  |                       |   |
+---------+      +----------------+    |  |  +----------------+   |   |      +----------------+
                                       |  |  | Quilkin        |   |   |      | Dedicated      |
                                       |  +--> (Server Proxy) +-------+      | Game Server    |
                                       |     |                |   |          |                |
                                       |     +----------------+   |          +----------------+
                                       |                          |
                                       |     +----------------+   |          +----------------+
                                       |     | Quilkin        |   |          | Dedicated      |
                                       |     | (Server Proxy) |   |          | Game Server    |
                                       |     |                |   |          |                |
                                       |     +----------------+   |          +----------------+
                                       +                          +
```

## Usage

`quilkin --filename="configuration.yaml"`

* Start with our [Project Overview](./docs/README.md).
* See [examples](./examples) folder for basic configuration examples.
* See [Filter documentation](./docs/extensions/filters/filters.md) for a list of filters, and their configuration options.

## Code of Conduct

Participation in this project comes under the [Contributor Covenant Code of Conduct](code-of-conduct.md)

## Development and Contribution

Please read the [contributing](CONTRIBUTING.md) guide for directions on writing code and submitting Pull Requests.

Quilkin is in active development - we would love your help in shaping its future!

## Building

To build a binary of Quilkin on your operating system of choice, first clone the repository.

```shell script
git clone https://github.com/googleforgames/quilkin.git
cd quilkin
git submodule update --init --recursive
```
We use several submodules, so make sure you have them downloaded and updated.

To build a production release version of the binary:

`cargo build --release`

## Community

There are lots of ways to engage with the Quilkin community:

* Here on [Github](https://github.com/googleforgames/quilkin) via 
  [issues](https://github.com/googleforgames/quilkin/issues) and 
  [pull requests](https://github.com/googleforgames/quilkin/pulls).
* Join our [mailing list](https://groups.google.com/forum/#!forum/quilkin-discuss), which also gives you access to
  our continuous integration builds.
* Join our [Discord chat server](https://discord.gg/mfBNZjBDnc).
* Follow up on [Twitter](https://twitter.com/quilkindev).

## Credits

Many concepts and architectural decisions where inspired by [Envoy Proxy](https://www.envoyproxy.io/). 
Huge thanks to that team for the inspiration they provided with all their hard work. 
 
## Licence

Apache 2.0
