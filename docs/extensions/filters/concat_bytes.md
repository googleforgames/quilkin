# ConcatBytes

The `ConcatBytes` filter's job is to add a byte packet to either the beginning or end of each UDP packet that passes
through. This is commonly used to provide an auth token to each packet, so they can be routed appropriately.  

#### Filter name
```text
quilkin.extensions.filters.concat_token.v1alpha1.ConcatBytes
```

### Configuration Examples
```rust
# let yaml = "
local:
  port: 7000
filters:
  - name: quilkin.extensions.filters.concat_bytes.v1alpha1.ConcatBytes
    config:
        strategy: Append
        bytes: MXg3aWp5Ng==
client:
  addresses:
    - 127.0.0.1:7001
  connection_id: MXg3aWp5Ng==
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.filters.len(), 1);
# quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

### Configuration Options

```yaml
properties:
  strategy:
    type: string
    default: "Append"
    description: |
      Either 'Append' or 'Prepend' to either append or prepend the `bytes` data to each packet filtered respectively.
  bytes:
    type: string
    description: |
      Base64 encoded string of the byte array to add to each packet as it is filtered.  
```

### Metrics

This filter currently exports no metrics.
