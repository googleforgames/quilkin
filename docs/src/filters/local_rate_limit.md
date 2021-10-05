# LocalRateLimit

The LocalRateLimit filter controls the frequency at which packets received downstream are forwarded upstream by the proxy.  
Rate limiting is done independently per source (IP, Port) combination.

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
  filter_chain:
    filters:
      - name: quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit
        config:
          max_packets: 1000
          period: 1
  endpoints:
    - address: 127.0.0.1:7001
# ";
#   let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_static_non_versioned_filters().unwrap().len(), 1);
#   quilkin::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
# }
```
To configure a rate limiter, we specify the maximum rate at which the proxy is allowed to forward packets. In the example above, we configured the proxy to forward a maximum of 1000 packets per second).

> Be aware that due to some optimizations in the current rate limiter implementation, the enforced maximum number of packets is not always exact.
> It is in theory possible that the rate limiter allows a few packets through, however in practice this would be a rare occurrence
> and the maximum number of such packets that is in the worse case `N-1` where `N` is the number of threads used to process packets.
> For example, a configuration allowing 1000 packets per second could potentially allow 1004 packets during some time window if we have up to 4 threads.

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
      The duration in seconds overwhich `max_packets` applies.
    default: 1 # 1 second
    minimum: 1

required: [ 'max_packets' ]
```


### Metrics

* `quilkin_filter_LocalRateLimit_packets_dropped`  
  A counter over the total number of packets that have exceeded the configured maximum rate limit and have been dropped as a result.
