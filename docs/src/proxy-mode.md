# Proxy Mode

The "proxy mode" is the primary mode of operation for Quilkin, wherein it acts as a non-transparent UDP proxy.

This is driven by Quilkin being [executed](./using.md#command-line-interface) via the 
[`proxy` subcommand](../api/quilkin/cli/struct.Proxy.html).

To view all the options for the `proxy` subcommand, run: 

```shell
$ quilkin proxy --help
{{#include ../../target/quilkin.run.commands}}
```
