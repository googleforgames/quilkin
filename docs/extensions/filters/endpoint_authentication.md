# EndpointAuthentication

The `EndpointAuthentication` filter's job is to ensure only authorised clients are able to send packets to Endpoints that
they have access to.

It does this via matching an authentication token found in the
[Filter dynamic metadata]`(TODO: add link to dynamic metadata docs)`, and comparing it to Endpoint's connection_id
values, and only letting packets through to those Endpoints if there is a match.

Capturing the authentication token from an incoming packet can be implemented via the [CaptureByte](./capture_bytes.md)
filter, with an example outlined below, or any other filter that populates the configured dynamic metadata key for the
authentication token to reside.

On the game client side the [ConcatenateBytes](./concatenate_bytes.md) filter can be used to add authentication tokens
to outgoing packets.

#### Filter name
```text
quilkin.extensions.filters.endpoint_authentication.v1alpha1.EndpointAuthentication
```

### Configuration Examples
```rust
# let yaml = "
local:
  port: 7000
filters:
  - name: quilkin.extensions.filters.capture_bytes.v1alpha1.CaptureBytes # This filter is often used in conjunction to capture the authentication token
    config:
        metadataKey: myapp.com/myownkey
        size: 3
        remove: true  
  - name: quilkin.extensions.filters.endpoint_authentication.v1alpha1.EndpointAuthentication
    config:
        metadataKey: myapp.com/myownkey
server:
  endpoints: 
    - name: Game Server No. 1
      address: 127.0.0.1:26000
      connection_ids:
        - MXg3aWp5Ng== # Authentication is provided by these ids, and matched against 
        - OGdqM3YyaQ== # the value stored in Filter dynamic metadata
    - name: Game Server No. 2
      address: 127.0.0.1:26001
      connection_ids:
        - bmt1eTcweA==
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.filters.len(), 2);
# quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

View the [CaptureBytes](./capture_bytes.md) filter documentation for more details.

### Configuration Options

```yaml
properties:
  metadataKey:
    type: string
    default: quilkin.dev/captured_bytes
    description: | 
      The key under which the captured bytes are stored in the Filter invocation values.
```

### Metrics

* `quilkin_filter_EndpointAuthentication_packets_dropped`  
  A counter of the total number of packets that have been dropped as they could not be authenticated against an
  Endpoint.
