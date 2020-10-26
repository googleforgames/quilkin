# AuthTokenCapture

The `AuthTokenCapture` filter's job is to find the authentication token within a given packet, and capture it in
the Filter's context object, under the key `"AUTHENTICATION_TOKEN"`, so that it can be utilised by routing filters
further down the chain.

This is often used in combination with [ConcatenateBytes](./concatenate_bytes.md) filter and `[[TODO: add router
filter name when ready]]` filter to provide common packet routing utilities.

#### Filter name
```text
quilkin.extensions.filters.auth_token_capture.v1alpha1.AuthTokenCapture
```

### Configuration Examples
```rust
# let yaml = "
local:
  port: 7000
filters:
  - name: quilkin.extensions.filters.auth_token_capture.v1alpha1.AuthTokenCapture
    config:
        strategy: BEGINNING
        byteCount: 3
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
       - END: Looks for the token at the end of the packet.
       - BEGINNING: looks for the token at the beginnning of the packet.
    default: "END"
    enum: ['BEGINNING', 'END']
  byteCount:
    type: integer
    description: |
      The number of bytes that are used in the packet for the authentication token
  remove:
    type: boolean
    default: false
    description: |
      Whether or not to remove the auth token from the packet before passing it along to the next filter in the chain.
```

### Metrics

This filter currently exports no metrics.