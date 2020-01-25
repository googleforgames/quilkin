# Quilkin

Quilkin is a non-transparent UDP proxy specifically designed for use with large scale multiplayer dedicated game servers
deployments, to ensure security, access control, telemetry data, metrics and more.
 
It is designed to be used behind game clients as well as in front of dedicated game servers.  

## Planned Roadmap

- [x] Sender: Configuration with a connection token
- [x] Receiver: Configuration of endpoints with multiple connection token attached, that provide routing 
- [ ] Basic non-transparent UDP forwarding from Sender to Receiver
- [ ] Basic non-transparent UDP forwarding from Receiver to all endpoints
- [ ] Simple UDP routing via an appended connection ID to UDP packet (sender and receiver implementation)
- [ ] QUIC based security and UDP routing (sender and receiver implementation)
- [ ] gRPC configuration management control plane API

## Project State

Project is currently in *alpha* status, and is being actively developed. Expect things to break.

Not to be used in production systems.

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
