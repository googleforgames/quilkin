### Dynamic Configuration using xDS Management Servers

In addition to static configuration provided upon startup, a Quiklin proxy's configuration can also be updated at runtime. The proxy can be configured on startup to talk to a set of management servers which provide it with updates throughout its lifecycle.

Communication between the proxy and management server uses the [xDS gRPC protocol][xDS], similar to an [envoy proxy]. xDS is one of the standard configuration mechanisms for software proxies and as a result, Quilkin can be setup to discover configuration resources from any API compatible server. Also, given that the protocol is [well specified][xDS-protocol], it is similarly straight-forward to implement a custom server to suit any deployment's needs.

> The [go-control-plane] project provides production ready implementations of the API on top of which custom servers can be built relatively easily.

As described within the [xDS-api] documentation, the xDS API comprises a set of resource discovery APIs, each serving a specific set of configuration resource types, while the protocol itself comes in several [variants][xds-variants].
Quilkin implements the **Aggregated Discovery Service (ADS)** _State of the World (SotW)_ variant with gRPC.

#### Supported APIs

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


#### Metrics

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


[xDS]: https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol#xds-rest-and-grpc-protocol
[envoy proxy]: https://www.envoyproxy.io/docs/envoy/latest/
[xDS-protocol]: https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol#the-xds-transport-protocol
[go-control-plane]: https://github.com/envoyproxy/go-control-plane
[xDS-api]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration
[CDS]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration#cds
[EDS]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration#eds
[LDS]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/operations/dynamic_configuration#lds
[cluster discovery type]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#enum-config-cluster-v3-cluster-discoverytype
[lbpolicy]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto#enum-config-cluster-v3-cluster-lbpolicy
[clapolicy]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/endpoint/v3/endpoint.proto#config-endpoint-v3-clusterloadassignment-policy
[locality]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto#config-core-v3-locality
[socket addresses]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/address.proto#config-core-v3-address
[filters-doc]: ./extensions/filters/filters.md
[listener-resource]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener.proto#config-listener-v3-listener
[xds-filters]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener_components.proto#envoy-v3-api-msg-config-listener-v3-filter
[xds-filter-chain]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/listener/v3/listener_components.proto#config-listener-v3-filterchain
[DiscoveryRequest]: https://www.envoyproxy.io/docs/envoy/latest/api-v2/api/v2/discovery.proto#envoy-api-msg-discoveryrequest
[xds-variants]: https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol#variants-of-the-xds-transport-protocol
[filter-protos]: ../proto/quilkin/extensions/filters
[filters-doc]: ./extensions/filters/filters.md
[xds-endpoint-metadata]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/base.proto#envoy-v3-api-msg-config-core-v3-metadata
[endpoint-metadata]: ./proxy.md#endpoint-metadata