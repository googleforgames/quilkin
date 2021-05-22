# Debug

The Debug filter logs all incoming and outgoing packets to standard output.

This filter is useful in debugging deployments where the packets strictly contain valid `UTF-8` encoded strings. A generic error message is instead logged if conversion from bytes to `UTF-8` fails.

#### Filter name
```text
quilkin.extensions.filters.debug_filter.v1alpha1.Debug
```

### Configuration Examples
```rust
# let yaml = "
version: v1alpha1
static:
  filters:
    - name: quilkin.extensions.filters.debug.v1alpha1.Debug
      config:
        id: debug-1
  endpoints:
    - address: 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_static_filters().unwrap().len(), 1);
# quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

### Configuration Options

```yaml
properties:
  id:
    type: string
    description: |
      An identifier that will be included with each log message.
```


### Metrics

This filter currently exports no metrics.
