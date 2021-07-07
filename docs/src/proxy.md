### Proxy

#### Concepts

##### Upstream Endpoint

An Upstream Endpoint represents a server that Quilkin forwards packets to.
It is represented by an IP address and port. An upstream endpoint can optionally be associated with a (potentially empty) set of tokens as well as metadata.

###### Endpoint Metadata

Arbitrary key value pairs that are associated with the endpoint.
These are visible to Filters when processing packets and can be used to provide more context about endpoints (e.g whether or not to route a packet to an endpoint).
Keys must be of type string otherwise the configuration is rejected.

Metadata associated with an endpoint contain arbitrary key value pairs which [Filters][filters-doc] can consult when processing packets (e.g they can contain information that determine whether or not to route a particular packet to an endpoint).

In fact, the tokens associated with an endpoint are simply a special piece of metadata well known to Quilkin and is used by the built-in [TokenRouter] filter to route packets.
Such well known values are placed within an object in the endpoint metadata, under the special key `quilkin.dev`. Currently, only the `tokens` entry is in use.

As an example, the following shows the configuration for an endpoint with its metadata:
```yaml
static:
  endpoints:
    - address: 127.0.0.1:26000
      metadata:
        canary: false
        quilkin.dev: # This object is extracted by Quilkin and is usually reserved for built-in features
          tokens:
            - MXg3aWp5Ng== # base64 for 1x7ijy6
            - OGdqM3YyaQ== # base64 for 8gj3v2i
```

An endpoint's metadata can be specified alongside the endpoint in [static configuration][proxy-configuration] or using the [xDS endpoint metadata][xds-endpoint-metadata] field when using [dynamic configuration][dynamic-configuration-doc] via xDS.

##### Session

A session represents ongoing communication flow between a client and an [Upstream Endpoint][endpoint]. See the [Session documentation][sessions-doc] for more information.

#### Metrics

The proxy exposes the following general metrics (See the metrics sub-sections for metrics specific to other Quilkin components, e.g for metrics related to packet flow see [sessions metrics][session-metrics], or metrics exported by individual filters can be found in the documentation for each filter):

- `quilkin_proxy_packets_dropped_total{reason}` (Counter)

  The total number of packets (not associated with any session) that were dropped by proxy.
  Not that packets reflected by this metric were dropped at an earlier stage before they were associated with any session. For session based metrics, see the list of [session metrics][session-metrics] instead.
  * `reason = NoConfiguredEndpoints`
    - `NoConfiguredEndpoints`: No upstream endpoints were available to send the packet to. This can occur e.g if the endpoints cluster was scaled down to zero and the proxy is configured via a control plane.

- `quilkin_cluster_active` (Gauge)

  The number of currently active clusters.

- `quilkin_cluster_active_endpoints` (Gauge)

  The number of currently active upstream endpoints. Note that this tracks the number of endpoints that the proxy knows of rather than those that it is connected to (see [Session Metrics][session-metrics] instead for those)

[sessions-doc]: ./session.md
[session-metrics]: ./session.md#metrics
[filters-doc]: ./extensions/filters/filters.md
[endpoint]: #upstream-endpoint
[proxy-configuration]: ./proxy-configuration.md
[xds-endpoint-metadata]: https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/endpoint/v3/endpoint_components.proto#envoy-v3-api-field-config-endpoint-v3-lbendpoint-metadata
[dynamic-configuration-doc]: ./xds.md
[TokenRouter]: ./extensions/filters/token_router.md
