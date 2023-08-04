# Administration

| services | ports | Protocol |
|----------|-------|-----------|
| Administration | 8000 | HTTP (IPv4 OR IPv6) |

## Logging
By default, Quilkin will log `INFO` level events, you can change this by setting
the `RUST_LOG` environment variable. See [`log` documentation][log-docs] for
more advanced usage.

> If you are debugging Quilkin set the `RUST_LOG` environment variable to `quilkin=trace`, to filter trace level
> logging to only Quilkin components.

>  Verbose logging in Quilkin will affect performance considerably, so we recommend only 
> turning it on for debugging purposes.

## HTTP API

Quilkin exposes an HTTP interface to query different aspects of the server.

> It is assumed that the administration interface will only ever be able to be accessible on `localhost`.

By default, the administration interface is bound to `[::]:8000`, but it can be
configured with the `--admin-address` CLI flag or the `QUILKIN_ADMIN_ADDRESS`
environment.

## Endpoints

The admin interface provides the following endpoints:

### /live

This provides a liveness probe endpoint, most commonly used in
[Kubernetes based systems](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-a-liveness-command).

Will return an HTTP status of 200 when all health checks pass.

### /ready

This provides a readiness probe endpoint, most commonly used in
[Kubernetes based systems](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-readiness-probes).

Depending on whether Quilkin is run in Proxy mode i.e. `quilkin proxy`, vs an xDS provider mode, such as `quilkin
manage agones`, will dictate how readiness is calculated:

#### Proxy Mode

Will return an HTTP status of 200 when there is at least one endpoint to send data to. This is primarily to ensure
that new proxies that have yet to get configuration information from an [xDS server](../services/xds.md) aren't send data
until they are fully populated.

#### xDS Provider Mode

Will return an HTTP status of 200 when all health checks pass.

### /metrics

Outputs [Prometheus](https://prometheus.io/) formatted metrics for this instance.

See the [Proxy Metrics](../services/proxy/metrics.md) documentation for what proxy metrics are available.

See the [xDS Metrics](../services/xds/metrics.md) documentation for what xDS metrics are available.

### /config

Returns a JSON representation of the cluster and filterchain configuration that the instance is running
with at the time of invocation.

[log-docs]: https://docs.rs/env_logger/latest/env_logger/#enabling-logging