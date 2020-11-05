# Filters

In most cases, we would like Quilkin to do some preprocessing of received packets before sending them off to their destination. Because this stage is entirely specific to the use case at hand and differs between Quilkin deployments, we must have a say over what tweaks to perform - this is where filters come in.

### Filters and Filter chain
A filter represents a step in the tweaking/decision-making process of how we would like to process our packets. For example, at some step, we might choose to append some metadata to every packet we receive before forwarding it while at a later step, choose not to forward packets that don't meet some criteria.

Quilkin lets us specify any number of filters and connect them in a sequence to form a packet processing pipeline similar to a <a href="https://en.wikipedia.org/wiki/Pipeline_(Unix)" target="_blank">Unix pipeline</a> - we call this pipeline a `Filter chain`. The combination of filters and filter chain allows us to add new functionality to fit every scenario without changing Quilkin's core.

As an example, say we would like to perform the following steps in our processing pipeline to the packets we receive.

* Append a predetermined byte to the packet.
* Compress the packet.
* Do not forward (drop) the packet if its compressed length is over 512 bytes.

We would create a filter corresponding to each step either by leveraging any [existing filters](#built-in-filters) that do what we want or [writing one ourselves](#writing-filters) and connect them to form the following filter chain:

```bash
append | compress | drop
```

When Quilkin consults our filter chain, it feeds the received packet into `append` and forwards the packet it receives (if any) from `drop` - i.e the output of `append` becomes the `input` into `compress` and so on in that order.

There are a few things we note here:

* Although we have in this example, a filter called `drop`, every filter in the filter chain has the same ability to *drop* or *update* a packet - if any filter drops a packet then no more work needs to be done regarding that packet so the next filter in the pipeline never has any knowledge that the dropped packet ever existed.

* The filter chain is consulted for every received packet, in the same order regardless of the direction of the packet - a packet received downstream will be fed into `append` and the result from `drop` is forwarded upstream - a packet received upstream will be fed into `append` and the result from `drop` is forwarded downstream.

* Exactly one filter chain is specified and used to process all packets that flow through Quilkin.

### Configuration Examples ###

```rust
# let yaml = "
local:
  port: 7000
filters:
  - name: quilkin.extensions.filters.debug_filter.v1alpha1.Debug
    config:
      id: debug-1
  - name: quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit
    config:
      max_packets: 10
      period: 500ms
client:
  addresses:
    - 127.0.0.1:7001
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.validate().unwrap(), ());
# assert_eq!(config.filters.len(), 2);
```

We specify our filter chain in the `.filters` section of the proxy's configuration which has takes a sequence of [FilterConfig](#filter-config) objects. Each object describes all information necessary to create a single filter.

The above example creates a filter chain comprising a [Debug](debug.md) filter followed by a [Rate limiter](./local_rate_limit.md) filter - the effect is that every packet will be logged and the proxy will not forward more than 20 packets per second.

> The sequence determines the filter chain order so its ordering matters - the chain starts with the filter corresponding the first filter config and ends with the filter corresponding the last filter config in the sequence.

### Built-in filters <a name="built-in-filters"></a>
Quilkin includes several filters out of the box.

| Filter                                    | Description                    |
| ----------------------------------------- | ------------------------------ |
| [Debug](debug.md)                | Logs every packet              |
| [LocalRateLimiter](./local_rate_limit.md) | Limit the frequency of packets. |
| [ConcatenateBytes](./concatenate_bytes.md) | Add authentication tokens to packets. |
| [CaptureBytes](capture_bytes.md) | Capture bytes from a packet into the Filter Context. |

### FilterConfig <a name="filter-config"></a>
Represents configuration for a filter instance.

```yaml
properties:
  name:
    type: string
    description: |
      Identifies the type of filter to be created.
      This value is unique for every filter type - please consult the documentation for the particular filter for this value.

  config:
    type: object
    description: |
      The configuration value to be passed onto the created filter.
      This is passed as an object value since it is specific to the filter's type and is validated by the filter
      implementation. Please consult the documentation for the particular filter for its schema.

required: [ 'name', 'config' ]
```
