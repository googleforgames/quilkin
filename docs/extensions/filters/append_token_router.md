# Append Token Router

Append Token Router is a simple Client/Server filter pair to provide routing from a Game Client to a Game Server
through a given set of Proxies via a fixed length `connection_id` value that is sent along as part of the UDP packet.

To implement this, the Client proxy appends the `client.connection_id` data value to the end of each packet that is sent
from the Game Client to a Server Proxy.

On the Server proxy side, on receiving the packet, strips the packet off the fixed length `connection_id` off the end
of the packet. Then that `connection_id` value is compared to the `server.endpoints.connection_ids`. Any values that
is matches, the UDP packet is sent on to the that Endpoint's destination.  
 
#### Filter name
```text
quilkin.extensions.filters.append_token_router.v1alpha1.AppendTokenRouter
```

### Configuration Examples: Client

```rust
# let yaml = "
local:
  port: 7000
filters:
  - name: quilkin.extensions.filters.append_token_router.v1alpha1.AppendTokenRouter
client:
  addresses:
    - 127.0.0.1:7001
  connection_id: MXg3aWp5Ng== # (string value: nkuy70x)
# ";

# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.validate().unwrap(), ());
# assert_eq!(config.filters.len(), 1);
# // TODO: make it possible to easily validate filter's config from here.
 ```

### Configuration Examples: Server

```rust
# let yaml = "
local:
  port: 7001
filters:
  - name: quilkin.extensions.filters.append_token_router.v1alpha1.AppendTokenRouter
    config:
        connection_id_bytes: 7
server:
  endpoints: # array of potential endpoints to send on traffic to
    - name: Game Server No. 1
      address: 127.0.0.1:26000
      connection_ids:
        - MXg3aWp5Ng== # the connection byte array to route to, encoded as base64 (string value: 1x7ijy6)
        - OGdqM3YyaQ== # (string value: 8gj3v2i)
    - name: Game Server No. 2
      address: 127.0.0.1:26001
      connection_ids:
        - bmt1eTcweA== # (string value: nkuy70x)
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.validate().unwrap(), ());
# assert_eq!(config.filters.len(), 1);
# // TODO: make it possible to easily validate filter's config from here.
```

### Configuration Options: Server

```yaml
properties:
  connection_id_bytes:
    type: integer
    description: |
      The number of bytes the `connection_id` takes up at the end of the packets.
```

### Metrics

Implemented soon!