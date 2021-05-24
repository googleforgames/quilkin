### Session

Quilkin uses the `Session` concept to track traffic flowing through the proxy between any client-server pair. A Session serves the same purpose, and can be thought of as a lightweight version of a `TCP` session in that, while a TCP session requires a protocol to establish and teardown:

- A Quilkin session is automatically created upon receiving the first packet from the client, to be sent to an upstream server.
- The session is automatically torn down after a period of inactivity (where no packet was sent between either party) - currently 60 seconds.

A session is identified by the 4-tuple `(client IP, client Port, server IP, server Port)` where the client is the downstream endpoint which initiated the communication with Quilkin and the server is one of the upstream endpoints that Quilkin proxies traffic to.

Sessions are established *after* the filter chain completes. The destination endpoint of a packet is determined by the filter chain, so a session can only be created after filter chain completion. For example, if the filter chain drops all packets, then no session will ever be created.

#### Metrics

The proxy exposes the following metrics around sessions:

- `quilkin_session_active` (Gauge)

  The number of currently active sessions.

- `quilkin_session_duration_secs` (Histogram)

  A histogram over how long sessions lasted before they were torn down. Note that, by definition, active sessions are not included in this metric.

- `quilkin_session_total` (Counter)

  The total number of sessions that have been created.

- `quilkin_session_rx_bytes_total` (Counter)

  The total number of bytes received from the upstream endpoint.

- `quilkin_session_rx_bytes_total` (Counter)

  The total number of bytes sent to the upstream endpoint.

- `quilkin_session_rx_packets_total` (Counter)

  The total number of packets received from the upstream endpoint.

- `quilkin_session_tx_packets_total` (Counter)

  The total number of packets sent to the upstream endpoint.

- `quilkin_session_packets_dropped_total` (Counter)

  The total number of packets received from the upstream endpoint which were dropped by the filter chain rather than forwarded to the downstream endpoint.

- `quilkin_session_rx_errors_total` (Counter)

  The total number of errors encountered while reading a packet from the upstream endpoint.

- `quilkin_session_rx_errors_total` (Counter)

  The total number of errors encountered while sending a packet to the upstream endpoint.
