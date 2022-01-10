#### XDS Management Server

This project contains an [XDS] management server implementation that configures
Quilkin proxies.
The task of a management server is to continuously check for updates to
upstream endpoints and filter configuration from some external source, and then use
that information to generate cluster and filter updates that is pushed to any connected
Quilkin proxy.

The project has two binaries depending on the external source of configuration:

1. **cmd/file/file.go** an implementation that watches a configuration file on disk and
   sends updates to proxies whenever that file changes.
   It can be started with the following command:
   ```sh
   go run cmd/file/file.go --config=config.yaml --port=18000
   ```
   After running this command, any proxy that connects to port 18000 will receive updates as
   configured in `config.yaml` file.
   The configuration file schema is:
   ```yaml
   # clusters contain a list of clusters.
   # Each entry represents a cluster configuration.
   clusters: [{
     # Name of the cluster.
     name: string

     # List of endpoints belonging to the cluster.
     # Each entry represents an upstream endpoint.
     endpoints: [{
       # The endpoint's IP address.
       ip: int
       # The endpoint's port.
       port: int
       # Opaque metadata that will be the endpoint's metadata.
       metadata: {}
     }]
   }]

   # filterchain represents the filter chain configuration.
   # It contains a list of filter configurations.
   filterchain: [{
     # Name of the filter
     name: string

     # typed_config contains the filter's configuration.
     typed_config: {
       # @type must be equivalent to name - the name of the filter.
       # It is an extra, required field.
       '@type': string
       # ...
       # The rest of the body contains filter specific configuration or
       # is empty if the filter has no configuration.
     }
   }]
   ```
   Example:
   ```yaml
   clusters:
   - name: cluster-a
     endpoints:
     - ip: 123.0.0.1
       port": 29
       metadata:
         'quilkin.dev':
            tokens:
            - "MXg3aWp5Ng=="
   filterchain:
   - name: quilkin.extensions.filters.debug.v1alpha1.Debug
     typed_config:
       '@type': quilkin.extensions.filters.debug.v1alpha1.Debug
       id: hello
   ```

   > The file.go binary is primarily an example and mostly suitable for demo purposes.
   > As a result, some configuration options and features might be missing.

1. **cmd/controller.go**: A server implementation that runs in [Kubernetes].
   
   1. Cluster information is retrieved from [Agones] - the server watches for `Allocated`
      [Agones GameServers] and exposes their IP address and Port as upstream endpoints to
      any connected Quilkin proxies.

      > Since an Agones GameServer can have multiple ports exposed, if multiple ports are in
      > use, the server looks for the port named `default` and picks that as the endpoint's
      > port (otherwise it picks the first port in the port list).

   1. Filter chain is configurable on a per-proxy basis. By default an empty filter chain is
      used and from there the filter chain can configured using annotations on the proxy's pod.
      The following annotations are currently supported:
      - **quilkin.dev/debug-packets**: If set to the value `true`, then a `Debug` filter will be
        added to the filter chain, causing all packets will be logged.
      - **quilkin.dev/routing-token-suffix-size**: Sets the size (in number of bytes) of routing tokens appended to
        packets. Extracted tokens will matched against available endpoints in order to figure out
        where to send the associated packet.
        Note that the token is stripped off the packet. This annotation cannot be provided together with
        `quilkin.dev/routing-token-prefix-size`.
      - **quilkin.dev/routing-token-prefix-size**: Works exactly the same as `quilkin.dev/routing-token-suffix-size`
        with the difference that the token is a prefix on the packet rather than a suffix.
   
   As an example, the following runs the server against a cluster (using default kubeconfig configuration) where Quilkin pods run in the `quilkin` namespace and game-server pods run in the `gameservers` namespace:

   ```sh
   go run controller.go -- port=18000 --proxy-namespace=quilkin --game-server-namespace=gameservers
   ```

   > A proxy's pod must have a `quilkin.dev/role` annotation set to the value `proxy` in order
     for the management server to detect the pod as a proxy and push updates to it.

   > Note that currently, the server can only discover resources within a single cluster.

   ##### Admin server

   In addition the gRPC server, a http server (configurable via `--admin-port`is also started to serve administrative functionality.
   The following endpoints are provided:
   - `/ready`: Readiness probe that returns a 5xx if communication with the Kubernetes api is problematic.
   - `/live`: Liveness probe that always returns a 200 response.
   - `/metrics`: Exposes Prometheus metrics.


[XDS]: https://www.envoyproxy.io/docs/envoy/latest/api-docs/xds_protocol
[Kubernetes]: https://kubernetes.io/
[Agones]: https://agones.dev/
[Agones GameServers]: https://agones.dev/site/docs/getting-started/create-gameserver/
