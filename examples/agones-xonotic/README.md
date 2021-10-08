# Agones & Xonotic Example

An example of running [Xonotic](https://xonotic.org/) with Quilkin on an [Agones](https://agones.dev/) cluster.

To interact with the demo, you will need to download the Xonotic client.

## Sidecar with no filter

Run `kubectl apply -f https://github.com/googleforgames/quilkin/blob/main/examples/agones-xonotic/sidecar.yaml` to 
create a Fleet of Xonotic dedicated game servers, with traffic processed through a Quilkin sidecar proxy.

This is particularly useful if you want to take advantage of the inbuilt metrics that Quilkin provides without 
having to alter your dedicated game server.

Connect to the Agones hosted Xonotic server via the "Multiplayer > Address" field in the Xonotic client.

## Sidecar with compression filter

Run `kubectl apply -f https://github.com/googleforgames/quilkin/blob/main/examples/agones-xonotic/sidecar-compress.yaml`
to create a Fleet of Xonotic dedicated game servers, with traffic processed through a Quilkin sidecar proxy, 
that is configured to decompresses UDP traffic with the [Snappy](../../docs/extensions/filters/compress.md#snappy) 
compression format.

Instead of connecting Xonotic directly, take the IP and port from the Agones hosted dedicated server, and replace the 
`${GAMESERVER_IP}` and `${GAMESERVER_PORT}` values in a local copy of `client-compress.yaml`. Run this configuration 
locally as:

`quilkin run -c ./client-compress.yaml`

From there connect to the local client proxy on "127.0.0.1:7000" via the "Multiplayer > Address" field in the 
Xonotic client, and Quilkin will take care of compressing the data for you without having to change either the 
client or the dedicated game server.

## Metrics

The Quilkin sidecars are also annotated with the 
[appropriate Prometheus annotations](https://github.com/prometheus-community/helm-charts/tree/main/charts/prometheus#scraping-pod-metrics-via-annotations)
to inform Prometheus on how to scrape the Quilkin proxies for metrics.
