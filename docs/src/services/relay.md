# xDS Control Plane

| services | ports | Protocol |
|----------|-------|-----------|
| ADS | 7800 | gRPC(IPv4) |
| CPDS | 7900 | gRPC(IPv4) |

For multi-cluster integration, Quilkin provides a `relay` service, that can be
used with a multiple [control plane](./xds.md) services to provide a unified
"Aggregated Discovery Service" endpoint.

To view all options for the `relay` subcommand, run:

```shell
$ quilkin relay --help
{{#include ../../../target/quilkin.manage.commands}}
```
