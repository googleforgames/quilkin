# iperf3 Performance Test

This example uses [iperf3](https://iperf.fr/) to perform a performance test on
Quilkin instance to look at throughput, jitter and packet loss.

## Requirements

* Docker

## Usage

This bash script sets up an iperf3 server, a Quilkin proxy from the main branch
with no filters, and an iperf3 client that sends data for 60 seconds.

```
docker build -t quilkin-iperf .
docker run -it quilkin-iperf
```

There are also a couple of build arguments and environment variables available
to be set, such as bandwidth and source.

### Build Arguments

- `install_args` — The arguments to pass to `cargo install` to install quilkin
  inside the image.

### Environment Variables

- `PARALLEL` — Number of parallel streams to test simultaneously.
  Default: (maximum: 128)
- `BANDWIDTH` — The bitrate for each stream. Default: 10Mbits/sec.
- `MTU` — The size of the packet payload. Default: 512 (The maximum size of a
  UDP packet with no IPv4 segmentation.)
- `PORT` — # The port for the iperf client, useful for comparing direct
  connections with proxied connections.

Several files are captured during the process and stored in `/quilkin`:

```
docker run -it -v /tmp/quilkin:/quilkin quilkin-iperf
```

* client.log - output from the iperf3 client.
* metrics.json - a copy of the Quilkin prometheus metrics on test completion.
* quilkin.log - output from Quilkin.
* server.log - output from the iperf3 server.
* socat.log - output from the socat tcp tunnel (usually empty).
