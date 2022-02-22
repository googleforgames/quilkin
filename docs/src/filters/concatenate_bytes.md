# ConcatenateBytes

The `ConcatenateBytes` filter's job is to add a byte packet to either the beginning or end of each UDP packet that passes
through. This is commonly used to provide an auth token to each packet, so they can be routed appropriately.  

#### Filter name
```text
quilkin.extensions.filters.concatenate_bytes.v1alpha1.ConcatenateBytes
```

### Configuration Examples
```rust
# let yaml = "
version: v1alpha1
static:
  filters:
    - name: quilkin.extensions.filters.concatenate_bytes.v1alpha1.ConcatenateBytes
      config:
          on_read: APPEND
          on_write: DO_NOTHING
          bytes: MXg3aWp5Ng==
  endpoints:
    - address: 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_static_filters().unwrap().len(), 1);
# quilkin::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

### Configuration Options ([Rust Doc](../../api/quilkin/filters/concatenate_bytes/struct.Config.html))

```yaml
{{#include ../../../target/quilkin.extensions.filters.concatenate_bytes.v1alpha1.yaml}}
```

### Metrics

This filter currently exports no metrics.
