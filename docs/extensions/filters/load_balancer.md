# LoadBalancer

The `LoadBalancer` filter distributes packets received downstream among all upstream endpoints.

#### Filter name
```text
quilkin.extensions.filters.load_balancer.v1alpha1.LoadBalancer
```

### Configuration Examples
```rust
# #[tokio::main]
# async fn main() {
#   let yaml = "
version: v1alpha1
static:
  filters:
    - name: quilkin.extensions.filters.load_balancer.v1alpha1.LoadBalancer
      config:
        policy: ROUND_ROBIN
  endpoints:
    - address: 127.0.0.1:7001
# ";
#   let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_static_filters().unwrap().len(), 1);
#   quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
# }
```

The load balancing policy (the strategy to use to select what endpoint to send traffic to) is configurable.
In the example above, packets will be distributed by selecting endpoints in turn, in round robin fashion

### Configuration Options

```yaml
properties:
  policy:
    type: string
    description: |
      The load balancing policy with which to distribute packets among endpoints.
    enum:
      - ROUND_ROBIN # Send packets by selecting endpoints in turn.
      - RANDOM      # Send packets by randomly selecting endpoints.
    default: ROUND_ROBIN
```

### Metrics

This filter currently does not expose any metrics.
