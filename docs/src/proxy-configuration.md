Proxy Configuration

The following is the schema and reference for a Quilkin proxy configuration file. See the [examples] folder for 
example configuration files.

By default Quilkin will look for a configuration file named `quilkin.yaml` in its current running directory first, 
then if not present, in `/etc/quilkin/quilkin.yaml` on UNIX systems. This can be overridden with the 
`-c/--config` command-line argument, or the `QUILKIN_FILENAME` environment variable.

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
        default: On linux, the machine hostname is used as default. On all other platforms a UUID is generated for the proxy.
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
      filter_chain:
        NOTE: Exactly of of `filters` or `versioned` can be specified
        filters: # A non versioned filter chain.
          '$ref': '#/definitions/filterchain'
        versioned: # Multiple versioned filter chains.
          '$ref': '#/definitions/versioned_filterchain'
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
      filter_chain:
        type: object
        description: |
          Configuration around any static behavior filter chains.
        properties:
          versioned:
            type: object
            description: |
              Version information for filter chains.
            properties:
              capture_version:
                '$ref': '#/definitions/capture_version'
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
  capture_version:
    type: object
    description: |
      Configures how to capture bytes containing version information from downstream packets.
    properties:
      strategy:
        type: string
        description: |
          The selected strategy for capturing the version from the incoming packet.
        enum:
        - SUFFIX: Retrieve bytes from the end of the packet.
        - PREFIX: Retrieve bytes from the beginnning of the packet.
        default: SUFFIX
      size:
        type: integer
        description: |
          The number of bytes in the packet to capture using the applied strategy.
      remove:
        type: boolean
        default: false
        description: |
          Whether or not to remove the captured bytes from the packet before passing it along to the next filter in the
          filter chain.
      required: ['strategy', 'size']
  versioned_filterchain:
    type object:
    description: |
      Configures a set of versioned filter chains and how to capture packet versions.
    properties:
      capture_version:
        '$ref': '#/definitions/capture_version'
    filter_chains:
      type: array
      description: |
        A set of filter chains and their associated versions.
      items:
        type: object
        properties:
          versions:
            type: array
            description: |
              A set of Standard base64 encoded (with padding) bytes.
              This contains the bytes that will be matched against any capture bytes from packets
              in order to select the corresponding filter chain.
              Note that the values must be unique across all filter chains - i.e there can't be
              ambiguity around what filter chain processes a packet.
            items
              type: string
              example: ['AA==']
          filters: # A filter chain.
            '$ref': '#/definitions/filterchain'
        required:
        - versions
        - filters
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

