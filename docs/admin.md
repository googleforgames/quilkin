# Administration Interface

Quilkin exposes an HTTP interface to query different aspects of the server.

> It is assumed that the administration interface will only ever be able to be accessible on `localhost`.

By default, the administration interface is bound to `[::]:9091`, but it can be configured through the 
[proxy configuration file](./proxy-configuration.md), like so:

```yaml
admin:
  address: [::]:9095
```

The admin interface provides the following endpoints:

## /metrics

Outputs [Prometheus](https://prometheus.io/) formatted metrics for this proxy.

See the [Proxy Metrics](./proxy.md#metrics) documentation for what metrics are available.
