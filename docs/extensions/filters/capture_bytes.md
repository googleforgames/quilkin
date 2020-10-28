# CaptureBytes

The `CaptureBytes` filter's job is to find a series of bytes within a packet, and capture it into
the Filter's Context object, so that it can be utilised by  filters further down the chain.

The captured bytes are stored in the `Values` Map that is available on all 
[Filter Context and Response objects]`(TODO: add link to filter context docs)`, using
the default key of `quilkin.dev/captured_bytes`, or a user supplied one via the configuration option `contextKey`.

This is often used as a way of retrieving authentication tokens from a packet, and used in combination with
[ConcatenateBytes](./concatenate_bytes.md) filter and 
`[[TODO: add router filter name when ready]]` filter to provide common packet routing utilities.

#### Filter name
```text
quilkin.extensions.filters.capture_bytes.v1alpha1.CaptureBytes
```

### Configuration Examples
```rust
# let yaml = "
local:
  port: 7000
filters:
  - name: quilkin.extensions.filters.capture_bytes.v1alpha1.CaptureBytes
    config:
        strategy: PREFIX
        contextKey: AUTHENTICATION_TOKEN
        size: 3
        remove: false
client:
  addresses:
    - 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.filters.len(), 1);
# quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

`[[TODO: update/link to routing examples once they are complete]]`

### Configuration Options

```yaml
properties:
  strategy:
    type: string
    description: |
      Implements the strategy for looking for the authentication token.
       - SUFFIX: Looks for the token at the end of the packet.
       - PREFIX: looks for the token at the beginnning of the packet.
    default: "SUFFIX"
    enum: ['PREFIX', 'SUFFIX']
  contextKey:
    type: string
    default: CAPTURED_BYTES
    description: | 
      The key in the `Values` Map that is a member on all Filter Context and Response objects, that the captured packets
      are stored against, so that the captured bytes can be passed between Filters.
  size:
    type: integer
    description: |
      The number of bytes in the packet to capture using the applied strategy.
  remove:
    type: boolean
    default: false
    description: |
      Whether or not to remove the captured bytes from the packet before passing it along to the next filter in the
      chain.
  required: ['size']
```

### Metrics

* `quilkin_filter_CaptureBytes_packets_dropped`  
  A counter of the total number of packets that have been dropped due to their length being less than the configured
  `size`.