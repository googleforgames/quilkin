# CaptureBytes

The `CaptureBytes` filter's job is to find a series of bytes within a packet, and capture it into
[Filter Dynamic Metadata][filter-dynamic-metadata], so that it can be utilised by filters further
down the chain.

This is often used as a way of retrieving authentication tokens from a packet, and used in combination with
[ConcatenateBytes](./concatenate_bytes.md) and 
[TokenRouter](token_router.md) filter to provide common packet routing utilities.

#### Filter name
```text
quilkin.extensions.filters.capture_bytes.v1alpha1.CaptureBytes
```

### Configuration Examples
```rust
# let yaml = "
version: v1alpha1
static:
  filters:
    - name: quilkin.extensions.filters.capture_bytes.v1alpha1.CaptureBytes
      config:
          strategy: PREFIX
          metadataKey: myapp.com/myownkey
          size: 3
          remove: false
  endpoints:
    - address: 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_static_filters().unwrap().len(), 1);
# quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

`[[TODO: update/link to routing examples once they are complete]]`

### Configuration Options

```yaml
properties:
  strategy:
    type: string
    description: |
      The selected strategy for capturing the series of bytes from the incoming packet.
       - SUFFIX: Retrieve bytes from the end of the packet.
       - PREFIX: Retrieve bytes from the beginnning of the packet.
    default: "SUFFIX"
    enum: ['PREFIX', 'SUFFIX']
  metadataKey:
    type: string
    default: quilkin.dev/captured_bytes
    description: | 
      The key under which the captured bytes are stored in the Filter invocation values.
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


[filter-dynamic-metadata]: ./filter.md#filter-dynamic-metadata
