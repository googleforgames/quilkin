# Control Plane Relay

| services | ports | Protocol |
|----------|-------|-----------|
| ADS | 7800 | gRPC(IPv4) |
| CPDS | 7900 | gRPC(IPv4) |

For multi-cluster integration, Quilkin provides a `relay` service, that can be
used with a multiple [control plane](./xds.md) services in different clusters to
provide a unified "Aggregated Discovery Service" endpoint for [proxy](./proxy.md)
services.

To connect to a control plane to a relay, add the `--relay` flag to your control
plane with the address of the relay. Then to connect a proxy service to the
relay's ADS endpoint, you use the same `--management-server` argument for
connecting to control planes.

To view all options for the `relay` subcommand, run:

```shell
$ quilkin relay --help
{{#include ../../../target/quilkin.relay.commands}}
```
