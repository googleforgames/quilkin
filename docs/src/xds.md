# Dynamic Configuration using xDS Management Servers

In addition to static configuration provided upon startup, a Quiklin proxy's configuration can also be updated at runtime. The proxy can be configured on startup to talk to a set of management servers which provide it with updates throughout its lifecycle.

Communication between the proxy and management server uses the [xDS gRPC protocol][xDS], similar to an [envoy proxy]. xDS is one of the standard configuration mechanisms for software proxies and as a result, Quilkin can be setup to discover configuration resources from any API compatible server. Also, given that the protocol is [well specified][xDS-protocol], it is similarly straight-forward to implement a custom server to suit any deployment's needs.

As described within the [xDS-api] documentation, the xDS API comprises a set of resource discovery APIs, each serving a specific set of configuration resource types, while the protocol itself comes in several [variants][xds-variants].
Quilkin implements the **Aggregated Discovery Service (ADS)** _State of the World (SotW)_ variant with gRPC.

## Supported APIs

Since the range of resources configurable by the xDS API extends that of Quilkin's domain (i.e being UDP based, Quilkin does not have a need for HTTP/TCP resources), only a subset of the API is supported. The following lists these relevant parts and any limitation to the provided support as a result:

- **Cluster Discovery Service [(CDS)][CDS]**: Provides information about known clusters and their membership information.
  * The proxy uses these resources to discover clusters and their endpoints.
  * While cluster topology information like [locality] can be provided in the configuration, the proxy currently does not use this information (support may be included in the future however).
  * Any [load balancing information][lbpolicy] included in this resource is ignored. For load balancing, use [Quilkin filters][filters-doc] instead.
  * Only [cluster discovery type] `STATIC` and `EDS` is supported. Configuration including other discovery types e.g `LOGICAL_DNS` is rejected.

- **Endpoint Discovery Service [(EDS)][EDS]**: Provides information about endpoints.
  * The proxy uses these resources to discover information about endpoints like their IP addresses.
  * Endpoints may provide [Endpoint Metadata][endpoint-metadata] via the [metadata][xds-endpoint-metadata] field. These metadata will be visible to filters as part of the corresponding endpoints information when processing packets.
  * Only [socket addresses] are supported on an endpoint's address configuration - i.e an IP address and port number combination. Configuration including any other type of addressing e.g named pipes will be rejected.
  * Any [load balancing information][clapolicy] included in this resource is ignored. For load balancing, use [Quilkin filters][filters-doc] instead.

- **Listener Discovery Service [(LDS)][LDS]**: Provides information about [Filters and Filter Chains][filters-doc].
  * Only the `name` and `filter_chains` fields in the [Listener resource][listener-resource] are used by the proxy. The rest are ignored.
  * Since Quilkin only uses one filter chain per proxy, at most one filter chain can be provided in the resource. Otherwise the configuration is rejected.
  * Only the list of [filters][xds-filters] specified in the [filter chain][xds-filter-chain] is used by the proxy - i.e other fields like `filter_chain_match` are ignored. This list also specifies the order that the corresponding filter chain will be constructed.
  * gRPC proto configuration for Quilkin's built-in filters [can be found here][filter-protos]. They are equivalent to the filter's static configuration.

## Available Providers
The server can be run by a quilkin commmand name _manage_.

 ### Agones

1. Cluster information is retrieved from [Agones] - the server watches for `Allocated`
   [Agones GameServers] and exposes their IP address and Port as [upstream endpoints][upstream-endpoint] to
   any connected Quilkin proxies.
   The set of tokens for the associated endpoint can be set by adding a comma separated standard base64 encoded strings.
   This must be added under an annotation `quilkin.dev/tokens` in the [GameServer][Agones GameServers]'s spec.
   For example:
   ```yaml
   annotations:
     Sets two tokens for the corresponding endpoint with values 1x7ijy6 and 8gj3v2i respectively.
     quilkin.dev/tokens: MXg3aWp5Ng==,OGdqM3YyaQ==
   ```

   > Since an Agones GameServer can have multiple ports exposed, if multiple ports are in
   > use, the server looks for the port named `default` and picks that as the endpoint's
   > port (otherwise it picks the first port in the port list).

2. Filter chain is configurable on a per-proxy basis. By default an empty filter chain is used and from there the filter chain can configured using a configMap named `quilkin-config` on the proxy's pod.

As an example, the following runs the server with subcommnad `manage agones` against a cluster (using default kubeconfig configuration) where Quilkin pods run in the `quilkin` namespace and game-server pods run in the `gameservers` namespace:

```sh
quilkin manage --port 18000 agones --config-namespace quilkin --gameservers-namespace gameservers
```

> A proxy's pod must have a `quilkin.dev/role` key in `quilkin-config` configMap set to the value `proxy` in order for the management server to detect the pod as a proxy and push updates to it.

> Note that currently, the server can only discover resources within a single cluster.

### Filesystem

The filesystem provider watches a configuration file on disk and sends updates to proxies whenever that file changes.

It can be started with using subcommnad `manage file` as the following:
```sh
quilkin manage --port 18000 file --config-file-path config.yaml
```

After running this command, any proxy that connects to port 18000 will receive updates as configured in `config.yaml` file.
You can find the configuration file schema here in [Proxy Configuration][proxy-configuration].

Example:
```yaml
clusters:
- name: cluster-a
  endpoints:
  - ip: 123.0.0.1
    port": 29
    metadata:
      'quilkin.dev':
         tokens:
         - "MXg3aWp5Ng=="
filters:
- name: quilkin.filters.debug.v1alpha1.Debug
  config:
    id: hello
```

To add an HTTP admin server, check out the [Administration][admin] page.

## Metrics

Quilkin exposes the following metrics around the management servers and its resources:

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


The following metrics are exposed by the management server.

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

[xDS]: https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol#xds-rest-and-grpc-protocol
[envoy proxy]: https://www.envoyproxy.io/docs/envoy/latest/
[xDS-protocol]: https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol#the-xds-transport-protocol
[xDS-api]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration
[CDS]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration#cds
[EDS]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration#eds
[LDS]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration#lds
[cluster discovery type]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#enum-config-cluster-v3-cluster-discoverytype
[lbpolicy]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#enum-config-cluster-v3-cluster-lbpolicy
[clapolicy]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/endpoint/v3/endpoint.proto#config-endpoint-v3-clusterloadassignment-policy
[locality]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto#config-core-v3-locality
[socket addresses]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/address.proto#config-core-v3-address
[filters-doc]: ./filters.md
[listener-resource]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener.proto#config-listener-v3-listener
[xds-filters]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener_components.proto#envoy-v3-api-msg-config-listener-v3-filter
[xds-filter-chain]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener_components.proto#config-listener-v3-filterchain
[DiscoveryRequest]: https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/discovery.proto#envoy-api-msg-discoveryrequest
[xds-variants]: https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol#variants-of-the-xds-transport-protocol
[filter-protos]: https://github.com/googleforgames/quilkin/tree/main/proto/quilkin/filters
[filters-doc]: ./filters.md
[xds-endpoint-metadata]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto#envoy-v3-api-msg-config-core-v3-metadata
[endpoint-metadata]: ./proxy.md#endpoint-metadata
[control-plane]: https://github.com/googleforgames/quilkin/tree/main/xds
[Agones]: https://agones.dev
[Kubernetes]: https://kubernetes.io/
[Agones GameServers]: https://agones.dev/site/docs/getting-started/create-gameserver/
[upstream-endpoint]: https://googleforgames.github.io/quilkin/main/book/proxy.html#upstream-endpoint
[proxy-configuration]: https://googleforgames.github.io/quilkin/main/book/proxy-configuration.html
[admin]: https://googleforgames.github.io/quilkin/main/book/admin.html
