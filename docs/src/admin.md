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

## /ready

This provides a readiness probe endpoint, most commonly used in 
[Kubernetes based systems](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-readiness-probes).

Depending on whether Quilkin is run in Proxy mode i.e. `quilkin run`, vs an xDS provider mode, such as `quilkin 
manage agones`, will dictate how readiness is calculated: 

### Proxy Mode:

Will return an HTTP status of 200 when there is at least one endpoint to send data to. This is primarily to ensure 
that new proxies that have yet to get configuration information from an [xDS server](./xds.md) aren't send data 
until they are fully populated. 

### xDS Provider Mode:

Will return an HTTP status of 200 when all health checks pass.

## /metrics

Outputs [Prometheus](https://prometheus.io/) formatted metrics for this proxy.

See the [Proxy Metrics](./proxy.md#metrics) documentation for what metrics are available.

## /config

Returns a JSON representation of the cluster and filterchain configuration that the proxy is running
with at the time of invocation.
