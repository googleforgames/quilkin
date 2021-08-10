# Quickstart: Quilkin with netcat

## Requirements

* A \*nix terminal
* A binary release of Quilkin from the [Github releases page](https://github.com/googleforgames/quilkin/releases)
* [ncat](https://nmap.org/ncat/guide/)
* [netcat](http://netcat.sourceforge.net/)

## 1. Start an udp echo service

So that we have a target for sending UDP packets to, let's use `ncat` to create a simple UDP echo process.

To do this run:

```shell
ncat -e $(which cat) -k -u -l 8000
```

This routes all UDP packets that `ncat` receives to the local `cat` process, which echoes it back.

## 2. Start Quilkin

Next, let's configure Quilkin, with a static configuration that points at the udp echo service we just started.

Open a new terminal and copy the following to a file named `proxy.yaml`:

```yaml
version: v1alpha1
static:
  endpoints:
    - address: 127.0.0.1:8000
```

This configuration will start Quilkin on the default port of 7000, and it will redirect all incoming UDP traffic to
a single endpoint of 127.0.0.1, port 8000.

Let's start Quilkin with the above configuration:

```shell
./quilkin --filename proxy.yaml
```

You should see an output like the following:

```shell
$ ./quilkin --filename proxy.yaml
{"msg":"Starting Quilkin","level":"INFO","ts":"2021-04-25T19:27:22.535174615-07:00","source":"run","version":"0.1.0-dev"}
{"msg":"Starting","level":"INFO","ts":"2021-04-25T19:27:22.535315827-07:00","source":"server::Server","port":7000}
{"msg":"Starting admin endpoint","level":"INFO","ts":"2021-04-25T19:27:22.535550572-07:00","source":"proxy::Admin","address":"[::]:9091"}
```

## 3. Send a packet!

In (yet 😃) another shell, let's use netcat to send an udp packet.

Run the following to connect netcat to Quilkin's receiving port of 7000 via UDP (`-u`):

```shell
nc -u 127.0.0.1 7000
```

Type the word "test" and hit enter, you should see it echoed back to you like so:

```shell
nc -u 127.0.0.1 7000
test
test
```

Feel free to send even more packets, as many as you would like 👍.

Congratulations! You have successfully routed a UDP packet and back again with Quilkin!

What's next?

* Run through the [Quilkin with Agones quickstart](./quickstart-agones-xonotic.md).
* Have a look at some of [the examples](https://github.com/googleforgames/quilkin/blob/main/examples) we have.
* Check out the [proxy configuration reference](./proxy-configuration.md) to what other configuration options are
  available.
