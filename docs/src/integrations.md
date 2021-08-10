# Quilkin Integration Examples

The Quilkin proxy can be integrated with your dedicated game servers in several ways,
each providing different capabilities and complexity tradeoffs.

Below captures several of the most useful and prevalent architectural patterns to give you inspiration
on how you can use Quilkin in your multiplayer game networking architecture.

## Server Proxy as a Sidecar

```text
                  +
                  |
               Internet
                  |
                  |
                  |
+---------+       |          +----------------+ +----------------+
|  Game   |       |          | Quilkin        | | Dedicated      |
|  Client <------------------> (Server Proxy) | | Game Server    |
+---------+       |          |                <->                |
                  |          +----------------+ +----------------+
                  |
                  |
                  |          +----------------+ +----------------+
                  |          | Quilkin        | | Dedicated      |
                  |          | (Server Proxy) | | Game Server    |
                  |          |                <->                |
                  |          +----------------+ +----------------+
                  |
                  |
                  |
                  +
```
This is the simplest integration and configuration option with Quilkin, but does provide the smallest number
of possible feature implementations and ability to provide redundancy.

That being said, this is a low risk way to integrate Quilkin, and take advantage of the out-of-the-box telemetry
and metric information that comes with Quilkin.

* In this example, the Server proxy is running alongside the dedicated game server - on the same public IP/machine/container.
   * This is often referred to as a sidecar pattern.
* Communication between the Server Proxy and the Dedicated Game Server occurs over the localhost network, with a
  separate port for each Game Client connection.
* Clients connect to the Server Proxy's public port/IP combination, and the Server Proxy routes all traffic directly
  to the dedicated game server.
* The Server Proxy can still use filters such as rate limiting, compression (forthcoming) or encryption (forthcoming),
  as long as the Game Client conforms to the standard protocols utilised by those filters as appropriate.

## Client Proxy to Sidecar Server Proxy

```text
                                    +
                                    |
                                 Internet
                                    |
                                    |
                                    |
+---------+    +----------------+   |        +----------------+ +----------------+
|  Game   |    | Quilkin        |   |        | Quilkin        | | Dedicated      |
|  Client <----> (Client Proxy) <------------> (Server Proxy) | | Game Server    |
+---------+    +----------------+   |        |                <->                |
                                    |        +----------------+ +----------------+
                                    |
                                    |
                                    |        +----------------+ +----------------+
                                    |        | Quilkin        | | Dedicated      |
                                    |        | (Server Proxy) | | Game Server    |
                                    |        |                <->                |
                                    |        +----------------+ +----------------+
                                    |
                                    |
                                    |
                                    +
```
This example is the same as the above, but puts a Client Proxy between the Game Client, and the Server Proxy to take
advantage of Client Proxy functionality.

* The Client Proxy may be integrated as a standalone binary, or directly into the client, with communication
  occurring over a localhost port.
* The Client Proxy can now utilise filters, such as, compression (forthcoming) and encryption (forthcoming), without
  having to change the Game Client.
* The Game Client will need to communicate to the Client Proxy what IP it should connect to when the Client is 
  match-made with a Game Server.

## Client Proxy to Separate Server Proxies Pools

```text
                                       +                          +
                                       |                          |
                                    Internet                   Private
                                       |                       Network
                                       |     +----------------+   |          +----------------+
                                       |     | Quilkin        |   |          | Dedicated      |
                                       |  +--> (Server Proxy) <-------+------> Game Server    |
+---------+      +----------------+    |  |  |                |   |   |      |                |
|  Game   |      | Quilkin        <-------+  +----------------+   |   |      +----------------+
|  Client <------> (Client Proxy) |    |  |                       |   |
+---------+      +----------------+    |  |  +----------------+   |   |      +----------------+
                                       |  |  | Quilkin        |   |   |      | Dedicated      |
                                       |  +--> (Server Proxy) <-------+      | Game Server    |
                                       |     |                |   |          |                |
                                       |     +----------------+   |          +----------------+
                                       |                          |
                                       |     +----------------+   |          +----------------+
                                       |     | Quilkin        |   |          | Dedicated      |
                                       |     | (Server Proxy) |   |          | Game Server    |
                                       |     |                |   |          |                |
                                       |     +----------------+   |          +----------------+
                                       +                          +

```

This is the most complex configuration, but enables the most reuse of Quilkin's functionality,
while also providing the most redundancy and security for your dedicated game servers.

* The Game client sends and receives packets from the Quilkin client proxy.
* The Client Proxy may be integrated as a standalone binary, or directly into the client, with communication
  occurring over a localhost port.
* The Client Proxy can utilise the full set of filters, such as routing, compression (forthcoming) and
    encryption (forthcoming), without having to change the Game Client.
* There are a hosted set of Quilkin Server proxies that have public IP addresses, and are connected
  to a [control plane](https://github.com/googleforgames/quilkin/issues/131) to coordinate routing and access control
  to the dedicated game servers, which are on private IP addresses.
* The Client Proxy is made aware of one or more Server proxies to connect to, possibly via their Game Client matchmaker
  or another service, with an authentication token to pass to the Server proxies, such that the UDP packets can be
  routed correctly to the dedicated game server they should connect to.
* Dedicated game servers receive traffic as per normal from the Server Proxies, and send data back to the proxies
  directly.     
* If the dedicated game server always expects traffic from only a single ip/port combination for client connection, 
  then traffic will always need to be sent through a single Server Proxy. Otherwise, UDP packets can be load
  balanced via the Client Proxy to multiple Server Proxies for even greater redundancy.


## What Next?

* Have a look at the [example configurations](https://github.com/googleforgames/quilkin/blob/main/examples) for basic configuration examples.
* Review the [set of filters](./extensions/filters/filters.md) that are available.

---

Diagrams powered by http://asciiflow.com/
