### Proxy


#### Metrics

The proxy exposes the following core metrics:

- `quilkin_proxy_packets_dropped_total{reason}` (Counter)

  The total number of packets (not associated with any session) that were dropped by proxy.
  Not that packets reflected by this metric were dropped at an earlier stage before they were associated with any session. For session based metrics, see the list of [session metrics][session-metrics] instead.
  * `reason = NoConfiguredEndpoints`
    - `NoConfiguredEndpoints`: No upstream endpoints were available to send the packet to. This can occur e.g if the endpoints cluster was scaled down to zero and the proxy is configured via a control plane.

[session-metrics]: ./session.md
