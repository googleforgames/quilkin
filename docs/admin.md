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

## /live

This provides a liveness probe endpoint, most commonly used in 
[Kubernetes based systems](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-a-liveness-command).

Will return an HTTP status of 200 when all health checks pass.

## /metrics

Outputs [Prometheus](https://prometheus.io/) formatted metrics for this proxy.

See the [Proxy Metrics](./proxy.md#metrics) documentation for what metrics are available.
