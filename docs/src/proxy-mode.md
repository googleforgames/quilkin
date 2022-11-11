# Proxy Mode

The "proxy mode" is the primary mode of operation for Quilkin, wherein it acts as a non-transparent UDP proxy.

This is driven by Quilkin being [executed](./using.md#command-line-interface) via the 
[`run` subcommand](../api/quilkin/cli/struct.Run.html).

To view all the options for the `run` subcommand, run: 

```shell
$ quilkin run --help
{{#include ../../target/quilkin.run.commands}}
```
