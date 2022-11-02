# Concatenate

`Concatenate` adds a metadata value to either the beginning or end of each UDP
packet that passes through it. This is commonly used to provide an auth token to
each packet, so they can be routed appropriately.  

#### Filter name
```text
quilkin.filters.concatenate.v1alpha1.Concatenate
```

### Configuration Examples
```rust
# let yaml = "
version: v1alpha1
filters:
  - name: quilkin.filters.concatenate.v1alpha1.Concatenate
    config:
        on_read: APPEND
        on_write: DO_NOTHING
        value: MXg3aWp5Ng==
clusters:
  default:
    localities:
        - endpoints:
            - address: 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.filters.load().len(), 1);
# quilkin::Proxy::try_from(config).unwrap();
```

### Configuration Options ([Rust Doc](../../api/quilkin/filters/concatenate/struct.Config.html))

```yaml
{{#include ../../../target/quilkin.filters.concatenate.v1alpha1.yaml}}
```

### Metrics

This filter currently exports no metrics.
