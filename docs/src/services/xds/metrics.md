# xDS Metrics

## Proxy Mode

Quilkin exposes the following metrics around the management servers and its resources when running as a
[UDP Proxy](../proxy.md):

- `quilkin_xds_connected_state` (Gauge)

  A boolean that indicates whether or not the proxy is currently connected to a management server. A value `1` means that the proxy is connected while `0` means that it is not connected to any server at that point in time.

- `quilkin_xds_update_attempt_total` (Counter)

  The total number of attempts made by a management server to configure the proxy. This is equivalent to the total number of configuration updates received by the proxy from a management server.

- `quilkin_xds_update_success_total` (Counter)

  The total number of successful attempts made by a management server to configure the proxy. This is equivalent to the total number of configuration updates received by the proxy from a management server and was successfully applied by the proxy.

- `quilkin_xds_update_failure_total` (Counter)

  The total number of unsuccessful attempts made by a management server to configure the proxy. This is equivalent to the total number of configuration updates received by the proxy from a management server and was rejected by the proxy (e.g due to a bad/inconsistent configuration).

- `quilkin_xds_requests_total` (Counter)

  The total number of [DiscoveryRequest]s made by the proxy to management servers. This tracks messages flowing in the direction from the proxy to the management server.


## xDS Provider Mode

The following metrics are exposed when Quilkin is running as an [xDS provider](../xds.md).

- `quilkin_management_server_connected_proxies` (Gauge)

  The number of proxies currently connected to the server.
- `quilkin_management_server_discovery_requests_total{request_type}` (Counter)

  The total number of xDS Discovery requests received across all proxies.
    - `request_type` = `type.googleapis.com/envoy.config.cluster.v3.Cluster` | `type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment` | `type.googleapis.com/envoy.config.listener.v3.Listener`
      Type URL of the requested resource
- `quilkin_management_server_discovery_responses_total` (Counter)

  The total number of xDS Discovery responses sent back across all proxies in response to Discovery Requests.
  Each Discovery response sent corresponds to a configuration update for some proxy.
    - `request_type` = `type.googleapis.com/envoy.config.cluster.v3.Cluster` | `type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment` | `type.googleapis.com/envoy.config.listener.v3.Listener`
      Type URL of the requested resource
- `quilkin_management_server_endpoints_total` (Gauge)

  The number of active endpoints discovered by the server. The number of active endpoints
  correlates with the size of the cluster configuration update sent to proxies.
- `quilkin_management_server_snapshot_generation_errors_total` (Counter)

  The total number of errors encountered while generating a configuration snapshot update for a proxy.
- `quilkin_management_server_snapshots_generated_total` (Counter)

  The total number of configuration snapshot generated across all proxies. A snapshot corresponds
  to a point in time view of a proxy's configuration. However it does not necessarily correspond
  to a proxy update - a proxy only gets the latest snapshot so it might miss intermediate
  snapshots if it lags behind.
- `quilkin_management_server_snapshots_cache_size` (Gauge)

  The current number of snapshots in the in-memory snapshot cache. This corresponds 1-1 to
  proxies that connect to the server. However the number may be slightly higher than the number
  of connected proxies since snapshots for disconnected proxies are only periodically cleared
  from the cache.

[DiscoveryRequest]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/discovery/v3/discovery.proto.html#service-discovery-v3-discoveryrequest
