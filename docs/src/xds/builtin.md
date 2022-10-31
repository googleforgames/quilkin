# Quilkin Built-in xDS Providers

To make xDS integration easier, Quilkin can be run in "xDS Provider Mode".

In this mode, rather than run Quilkin as a proxy, Quilkin will start an xDS management server on the 
[Local Port](../proxy/concepts.md#local-port), 
with each provider abstracting away the complexity of a full xDS management control plane via integrations with 
popular projects and artchitecture patterns.

This is driven by Quilkin being [executed](../using.md#command-line-interface) via the
[`manage` subcommand](../../api/quilkin/cli/struct.Manage.html), and specifying which provider to be used.

To view all the providers and options for the `manage` subcommand, run:

```shell
$ quilkin manage --help
{{#include ../../../target/quilkin.manage.commands}}
```

