# Compress

The `Compress` filter's job is to provide a variety of compression implementations for compression 
and subsequent decompression of UDP data when sent between systems, such as a game client and game server.

Depending on the `direction` configuration option, the proxy expects data to be sent to it either compressed or 
decompressed (i.e. its original format), where it will be subsequently compressed or decompressed respectively when 
being sent back out. 

The order and direction of compression and decompression of data based on the `direction` configuration is as follows:

| Direction   | Listening port expects ➡ Endpoint sends | Endpoint expects ➡ Listening port sends | 
| ----------- | ----------------------------------- | ------------------------------------ |
| UPSTREAM    | Decompressed ➡ Compressed           | Compressed ➡ Decompressed            |
| DOWNSTREAM  | Compressed ➡ Decompressed           | Decompressed ➡ Compressed            |

A common use case would be that a game client sending data to a locally running proxy, would be configured with the 
`UPSTREAM` direction (as compressed data is moving "upstream"), and a proxy that sat in front of a dedicated game 
server would have the`DOWNSTREAM` direction configuration (as compressed data is moving "downstream").

When configuring your filters, it will be important to note the order in which the `Compress` filter is placed in 
your [Filter configuration](filters.md) as it does mutate the packet data.

Currently, this filter only provides the Snappy ([original](https://github.com/google/snappy),
[rust](https://github.com/BurntSushi/rust-snappy)) compression method, but more will be
provided in the future.

#### Filter name
```text
quilkin.extensions.filters.compress.v1alpha1.Compress
```

### Configuration Examples
```rust
# let yaml = "
version: v1alpha1
static:
  filters:
    - name: quilkin.extensions.filters.compress.v1alpha1.Compress
      config:
          mode: SNAPPY
          direction: DOWNSTREAM
  endpoints:
    - name: server-1
      address: 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_filters().len(), 1);
# quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

### Configuration Options

```yaml
properties:
  required:
    - direction
  direction:
    type: string
    enum:
      - UPSTREAM
      - DOWNSTREAM
    description: |
      Compression direction (and decompression goes the other way).
  mode:
    type: string
    description: |
      The compression implementation to use on the incoming and outgoing packets.
    default: "SNAPPY"
    enum: 
      - SNAPPY
```

### Metrics
* `quilkin_filter_Compress_packets_dropped_total`
  Total number of packets dropped as they could not be processed. Labels: operation.
* `quilkin_filter_Compress_decompressed_bytes_total`
  Total number of decompressed bytes either received or sent.
* `quilkin_filter_Compress_compressed_bytes_total`
  Total number of compressed bytes either received or sent.
