# TokenRouter

The `TokenRouter` filter's job is to provide a mechanism to declare which Endpoints a packet should be sent to.   

This Filter provides this functionality by comparing a byte array token found in the
[Filter dynamic metadata]`(TODO: add link to dynamic metadata docs)` from a previous Filter, and comparing it to
Endpoint's connection_id values, and sending packets to those Endpoints only if there is a match.

#### Filter name
```text
quilkin.extensions.filters.token_router.v1alpha1.TokenRouter
```

### Configuration Examples
```rust
# let yaml = "
version: v1alpha1
static:
  filters:
    - name: quilkin.extensions.filters.token_router.v1alpha1.TokenRouter
      config:
          metadataKey: myapp.com/myownkey
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
# assert_eq!(config.source.get_static_filters().unwrap().len(), 1);
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
      The key under which the token is stored in the Filter dynamic metadata.
```

### Metrics

* `quilkin_filter_TokenRouter_packets_dropped`  
  A counter of the total number of packets that have been dropped. This is also provided with a `Reason` label, as there
  are differing reasons for packets to be dropped:
    * `NoEndpointMatch` - The token provided via the Filter dynamic metadata does not match any Endpoint's connection
     ids.
    * `NoTokenFound` - No token has been found in the Filter dynamic metadata.
    * `InvalidToken` - The data found for the token in the Filter dynamic metadata is not of the correct data type
       (Vec<u8>)

### Sample Applications

#### Packet Authentication

In combination with several other filters, the `TokenRouter` can be utilised as an authentication and access control
mechanism for all incoming packets.

Capturing the authentication token from an incoming packet can be implemented via the [CaptureByte](./capture_bytes.md)
filter, with an example outlined below, or any other filter that populates the configured dynamic metadata key for the
authentication token to reside.

For example, a configuration would look like:

```rust
# let yaml = "
version: v1alpha1
static:
  filters:
    - name: quilkin.extensions.filters.capture_bytes.v1alpha1.CaptureBytes # Capture and remove the authentication token
      config:
          size: 3
          remove: true
    - name: quilkin.extensions.filters.token_router.v1alpha1.TokenRouter
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
# assert_eq!(config.source.get_static_filters().unwrap().len(), 2);
# quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

On the game client side the [ConcatenateBytes](./concatenate_bytes.md) filter could also be used to add authentication
tokens to outgoing packets.
