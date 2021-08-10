Proxy Configuration

The following is the schema and reference for a Quilkin proxy configuration file. See the [examples] folder for example configuration files.

By default Quilkin will look for a configuration file named `quilkin.yaml` in its current running directory first, then if not present, in `/etc/quilkin/quilkin.yaml` on UNIX systems. This can be overridden with the `-f/--filename` command-line argument, or the `QUILKIN_FILENAME` environment variable.

```yaml
type: object
properties:
  version:
    type: string
    description: |
      The configuration file version to use.
    enum:
      - v1alpha1
  proxy:
    type: object
    description: |
      Configuration of core proxy behavior.
    properties:
      id:
        type: string
        description: |
          An identifier for the proxy instance.
        default: <uuid> A unique ID is generated for the proxy.
      port:
        type: integer
        description: |
          The listening port for the proxy.
        default: 7000
  admin:
    type: object
    description: |
      Configuration of proxy admin HTTP interface.
    properties:
      address:
      type: string
      description: |
        Socket Address and port to bind the administration interface to.
      default: [::]:9091
  static:
    type: object
    description: |
      Static configuration of endpoints and filters.
      NOTE: Exactly one of `static` or `dynamic` can be specified.
    properties:
      filter:
        '$ref': '#/definitions/filterchain'
      endpoints:
        '$ref': '#/definitions/endpoints'
    required:
      - endpoints
  dynamic:
    type: object
    description: |
      Dynamic configuration of endpoints and filters.
      NOTE: Exactly one of `static` or `dynamic` can be specified.
    properties:
      management_servers:
        type: array
        description: |
          A list of XDS management servers to fetch configuration from.
          Multiple servers can be provided for redundancy for the proxy to
          fall back to upon error.
        items:
          type: object
            description: |
              Configuration for a management server.
            properties:
              address:
                type: string
                description: |
                  Address of the management server. This must have the `http(s)` scheme prefix.
                  Example: `http://example.com`
    required:
      - management_servers

required:
  - version

definitions:
  filterchain:
    type: array
    description: |
      A filter chain.
    items:
      '$ref': {} # Refer to the Filter documentation for a filter configuration schema.
  endpoints:
    type: array
    description: |
      A list of upstream endpoints to forward packets to.
    items:
      type: object
        description: |
          An upstream endpoint
        properties:
          address:
            type: string
            description: |
              Socket address of the endpoint. This must be of the ´IP:Port` form e.g `192.168.1.1:7001`
            metadata:
              type: object
              description: |
                Arbitrary key value pairs that is associated with the endpoint.
                These are visible to Filters when processing packets and can be used to provide more context about endpoints (e.g whether or not to route a packet to an endpoint).
                Keys must be of type string otherwise the configuration is rejected.
      required:
        - address
```

[examples]: https://github.com/googleforgames/quilkin/blob/main/examples

