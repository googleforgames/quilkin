Proxy Configuration

The following is the schema and reference for a Quilkin proxy configuration file. See the [examples] folder for example configuration files.

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
      mode:
      type: string
      description: |
        The mode in which the proxy should run.
      enum:
        - SERVER
        - CLIENT
      default: SERVER
  admin:
    type: object
    description: |
      Configuration of operational proxy behavior.
    properties:
      metrics:
      type: object
      description: |
        Metrics related configuration.
      properties:
        port:
          type: integer
          description: |
            Port on which to expose metrics.
          default: 9091
  static:
    type: object
    description: |
      Static configuration of endpoints and filters.
    properties:
      filter:
        '$ref': '#/definitions/filterchain'
      endpoints:
        '$ref': '#/definitions/endpoints'
    required:
      - endpoints

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
```

[examples]: ../examples

