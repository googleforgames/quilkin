# Compress

The `Compress` filter's job is to provide a variety of compression implementations for compression
and subsequent decompression of UDP data when sent between systems, such as a game client and game server.

## Filter name

```text
quilkin.filters.compress.v1alpha1.Compress
```

## Configuration Examples

```rust
# let yaml = "
version: v1alpha1
filters:
  - name: quilkin.filters.compress.v1alpha1.Compress
    config:
        on_read: COMPRESS
        on_write: DECOMPRESS
        mode: SNAPPY
clusters:
  - endpoints:
    - address: 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.filters.load().len(), 1);
```

The above example shows a proxy that could be used with a typical game client, where the original client data is
sent to the local listening port and then compressed when heading up to a dedicated game server, and then
decompressed when traffic is returned from the dedicated game server before being handed back to game client.

> It is worth noting that since the Compress filter modifies the *entire packet*, it is worth paying special
  attention to the order it is placed in your [Filter configuration](../filters.md). Most of the time it will likely be
  the first or last Filter configured to ensure it is compressing the entire set of data being sent.

## Configuration Options ([Rust Doc](../../../../api/quilkin/filters/compress/struct.Config.html))

```yaml
{{#include ../../../../../target/quilkin.filters.compress.v1alpha1.yaml}}
```

## Compression Modes

### Snappy

> Snappy is a compression/decompression library. It does not aim for maximum compression, or compatibility with any
> other compression library; instead, it aims for very high speeds and reasonable compression.

This compression method is provided by [rust-snappy](https://github.com/BurntSushi/rust-snappy).

```yaml
- name: quilkin.filters.compress.v1alpha1.Compress
    config:
        on_read: COMPRESS
        on_write: DECOMPRESS
        mode: SNAPPY
```

### LZ4

> LZ4 is lossless compression algorithm, providing compression speed > 500 MB/s per core, scalable with multi-cores CPU.
> It features an extremely fast decoder, with speed in multiple GB/s per core, typically reaching RAM speed limits on
> multi-core systems.

This compression method is provided by [lz4_flex](https://github.com/PSeitz/lz4_flex).

```yaml
- name: quilkin.filters.compress.v1alpha1.Compress
    config:
        on_read: COMPRESS
        on_write: DECOMPRESS
        mode: LZ4
```

## Metrics

* `quilkin_filter_int_counter{label="compressed_bytes_total"}`
  Total number of compressed bytes either received or sent.
* `quilkin_filter_int_counter{label="decompressed_bytes_total"}`
  Total number of decompressed bytes either received or sent.
