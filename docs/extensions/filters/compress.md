# Compress

The `Compress` filter's job is to provide a variety of compression implementations for compression 
and subsequent decompression of UDP data when sent between systems, such as a game client and game server.

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
          on_read: COMPRESS
          on_write: DECOMPRESS
          mode: SNAPPY
  endpoints:
    - address: 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.source.get_static_filters().unwrap().len(), 1);
# quilkin::proxy::Builder::from(std::sync::Arc::new(config)).validate().unwrap();
```

The above example shows a proxy that could be used with a typical game client, where the original client data is 
sent to the local listening port and then compressed when heading up to a dedicated game server, and then 
decompressed when traffic is returned from the dedicated game server before being handed back to game client. 

> It is worth noting that since the Compress filter modifies the *entire packet*, it is worth paying special
  attention to the order it is placed in your [Filter configuration](filters.md). Most of the time it will likely be
  the first or last Filter configured to ensure it is compressing the entire set of data being sent.

### Configuration Options

```yaml
properties:
  on_read:
    '$ref': '#/definitions/action'
    description: |
      Whether to compress, decompress or do nothing when reading packets from the local listening port
  on_write:
    '$ref': '#/definitions/action'
    description: |
      Whether to compress, decompress or do nothing when writing packets to the local listening port
  mode:
    type: string
    description: |
      The compression implementation to use on the incoming and outgoing packets. See "Compression Modes" for details.
    enum:
      - SNAPPY
    default: SNAPPY

definitions:
  action:
    type: string
    enum:
      - DO_NOTHING
      - COMPRESS
      - DECOMPRESS
    default: DO_NOTHING
```

#### Compression Modes

##### Snappy

> Snappy is a compression/decompression library. It does not aim for maximum compression, or compatibility with any 
> other compression library; instead, it aims for very high speeds and reasonable compression.

Currently, this filter only provides the [Snappy](http://google.github.io/snappy/) compression format via the
[rust-snappy](https://github.com/BurntSushi/rust-snappy) crate, but more will be
provided in the future.

### Metrics
* `quilkin_filter_Compress_packets_dropped_total`
  Total number of packets dropped as they could not be processed.  
    * Labels:
      * `action`: The action that could not be completed successfully, thereby causing the packet to be dropped.
        * `Compress`: Compressing the packet with the configured `mode` was attempted.
        * `Decompress` Decompressing the packet with the configured `mode` was attempted.
* `quilkin_filter_Compress_decompressed_bytes_total`
  Total number of decompressed bytes either received or sent.
* `quilkin_filter_Compress_compressed_bytes_total`
  Total number of compressed bytes either received or sent.
