# Firewall

The `Firewall` filter's job is to allow or block traffic depending on if the incoming traffic's IP and port matches
the rules set on the Firewall filter.

#### Filter name
```text
quilkin.filters.firewall.v1alpha1.Firewall
```

### Configuration Examples
```rust
# let yaml = "
version: v1alpha1
filters:
  - name: quilkin.filters.firewall.v1alpha1.Firewall
    config:
      on_read:
        - action: ALLOW
          source: 192.168.51.0/24
          ports:
             - 10
             - 1000-7000
      on_write: 
        - action: DENY
          source: 192.168.51.0/24
          ports:
             - 7000
clusters:
  default:
    localities:
        - endpoints:
            - address: 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.filters.load().len(), 1);
# quilkin::Server::try_from(config).unwrap();
```

### Configuration Options ([Rust Doc](../../api/quilkin/filters/firewall/struct.Config.html))

```yaml
{{#include ../../../target/quilkin.filters.firewall.v1alpha1.yaml}}
```

#### Rule Evaluation

The Firewall filter supports DENY and ALLOW actions for access control. When multiple DENY and ALLOW actions are used 
for a workload at the same time, the evaluation is processed in the order it is configured, with the first matching 
rule deciding if the request is allowed or denied:

1. If a rule action is ALLOW, and it matches the request, then the entire request is allowed.
2. If a rule action is DENY and it matches the request, then the entire request is denied.
3. If none of the configured rules match, then the request is denied.

### Metrics

* `quilkin_filter_Firewall_packets_denied_total` Total number of packets denied.
* `quilkin_filter_Firewall_packets_allowed_total` Total number of packets allowed.

Both metrics have the label `event`, with a value of `read` or `write` which corresponds to either `on_read` or 
`on_write` events within the Filter.

[filter-dynamic-metadata]: ./filter.md#filter-dynamic-metadata
