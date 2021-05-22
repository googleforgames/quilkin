# LocalRateLimit

The LocalRateLimit filter controls the frequency at which packets received downstream are forwarded upstream by the proxy.

#### Filter name
```text
quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit
```

### Configuration Examples
```rust
# // Wrap this example within an async main function since the
# // local_rate_limit filter spawns a task on initialization
# #[tokio::main]
# async fn main() {
#   let yaml = "
version: v1alpha1
static:
  filters:
    - name: quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit
      config:
        max_packets: 1000
        period: 500ms
  endpoints:
    - address: 127.0.0.1:7001
# ";
#   let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_static_filters().unwrap().len(), 1);
#   quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
# }
```
To configure a rate limiter, we specify the maximum rate at which the proxy is allowed to forward packets. In the example above, we configured the proxy to forward a maximum of 1000 packets per 500ms (2000 packets/second).

> Packets that that exceeds the maximum configured rate are dropped.

### Configuration Options

```yaml
properties:
  max_packets:
    type: integer
    description: |
      The maximum number of packets allowed to be forwarded over the given duration.
    minimum: 0

  period:
    type: string
    description: |
      A human readable duration overwhich `max_packets` applies.
      Examples: `1s` 1 second, `500ms` 500 milliseconds.
      The minimum allowed value is 100ms.
    default: '1s' # 1 second

required: [ 'max_packets' ]
```


### Metrics

* `quilkin_filter_LocalRateLimit_packets_dropped`  
  A counter over the total number of packets that have exceeded the configured maximum rate limit and have been dropped as a result.
