# Quilkin

Quilkin is a non-transparent UDP proxy specifically designed for use with large scale multiplayer dedicated game servers
deployments, to ensure security, access control, telemetry data, metrics and more.
 
It is designed to be used behind game clients as well as in front of dedicated game servers.  

## Planned Roadmap

- [x] Client Proxy: Configuration with a connection token
- [x] Server Proxy: Configuration of endpoints with multiple connection token attached, that provide routing 
- [x] Basic non-transparent UDP forwarding from Client Proxy to Server Proxy
- [x] Basic non-transparent UDP forwarding from Server Proxy to all Endpoints
- [ ] Simple UDP routing via an appended connection ID to UDP packet (Client and Server Proxy implementation)
- [ ] QUIC based security and UDP routing (Client and Server Proxy implementation)
- [ ] gRPC configuration management control plane API
- [ ] Add Open Telemetry metrics

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

See [examples](./examples) folder for configuration examples.

## Code of Conduct

Participation in this project comes under the [Contributor Covenant Code of Conduct](code-of-conduct.md)

## Development and Contribution

Please read the [contributing](CONTRIBUTING.md) guide for directions on writing code and submitting Pull Requests.

Quilkin is in active development - we would love your help in shaping its future!

### Building

`cargo build`

### Testing

`cargo test`

## Credits

Many concepts and architectural decisions where inspired by [Envoy Proxy](https://www.envoyproxy.io/). 
Huge thanks to that team for the inspiration they provided with all their hard work. 

## Licence

Apache 2.0
