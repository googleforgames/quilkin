# Matches

The `Matches` filter's job is to provide a mechanism to change behaviour based
on dynamic metadata. This filter behaves similarly to the `match` expression
in Rust or `switch` statements in other languages.

#### Filter name
```text
quilkin.extensions.filters.matches.v1alpha1.Matches
```

### Configuration Examples
```rust
# let yaml = "
version: v1alpha1
static:
  endpoints:
    - address: 127.0.0.1:26000
    - address: 127.0.0.1:26001
  filters:
    - name: quilkin.extensions.filters.capture_bytes.v1alpha1.CaptureBytes
      config:
          strategy: PREFIX
          metadataKey: myapp.com/token
          size: 3
          remove: false
    - name: quilkin.extensions.filters.matches.v1alpha1.Matches
      config:
          on_read:
            metadataKey: myapp.com/token
            branches:
                - value: abc
                  filter: quilkin.extensions.filters.concatenate_bytes.v1alpha1.ConcatenateBytes
                  config:
                    on_read: APPEND
                    bytes: eHl6 # "xyz"
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_static_filters().unwrap().len(), 1);
# quilkin::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

View the [Matches](../../api/quilkin/filters/matches/struct.Config.html) filter documentation for more details.
