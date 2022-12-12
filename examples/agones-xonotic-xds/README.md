# Agones & Xonotic Example

An example of running [Xonotic](https://xonotic.org/) with Quilkin on an [Agones](https://agones.dev/) cluster, 
utlising the Quilkin xDS Agones provider, with a TokenRouter to provide routing and access control to the 
allocated `GameServer` instance.

To interact with the demo, you will need to download the Xonotic client and an existing Agones Kubernetes cluster.

## Installation on the Cluster 

To install Quilkin as an Agones integrated xDS control plane, we can create a deployment of Quilkin running in 
`manage agones` mode, with the appropriate permissions. 

```shell
$ kubectl apply -f ./xds-control-plane.yaml
configmap/quilkin-xds-filter-config created
serviceaccount/quilkin-agones created
clusterrole.rbac.authorization.k8s.io/quilkin-agones created
rolebinding.rbac.authorization.k8s.io/quilkin-agones created
deployment.apps/quilkin-manage-agones created
service/quilkin-manage-agones created
$ kubectl get pods
NAME                                     READY   STATUS    RESTARTS   AGE
quilkin-manage-agones-68b47457d4-42fxl   1/1     Running   0          3s
```

This also creates an internal `Service` endpoint for our Quilkin proxy instances to connect to named
`quilkin-manage-agones`.

To install the Quilkin Proxy pool which connects to the above xDS provider, we can split up a Deployment of Quilkin 
instances that point to the aforementioned Service, like so: 

```shell
$ kubectl apply -f ./proxy-pool.yaml
deployment.apps/quilkin-proxies created
service/quilkin-proxies created
$ kubectl get pods
NAME                                     READY   STATUS    RESTARTS   AGE
quilkin-manage-agones-68b47457d4-42fxl   1/1     Running   0          20m
quilkin-proxies-7448987cfb-6kbsz         1/1     Running   0          3s
quilkin-proxies-7448987cfb-p6krc         1/1     Running   0          3s
quilkin-proxies-7448987cfb-s9gxz         1/1     Running   0          3s
```

We can now see that we have 3 proxies running alongside and connected to our xDS provider.

## Create the `Fleet`

Next, create the `Fleet` of Xonotic `GameServer` instances:

```shell
$ kubectl apply -f ./fleet.yaml
fleet.agones.dev/xonotic created
$ kubectl get gameservers # run until they are Ready
NAME                  STATE   ADDRESS         PORT   NODE                               AGE
xonotic-d7rfx-55j7q   Ready   34.168.170.51   7226   gke-agones-default-534a3f8d-ifpc   34s
xonotic-d7rfx-nx7xr   Ready   34.168.170.51   7984   gke-agones-default-534a3f8d-ifpc   34s
xonotic-d7rfx-sn5d6   Ready   34.168.170.51   7036   gke-agones-default-534a3f8d-ifpc   34s
```

To let the Quilkin xDS provider know what token will route to which `GameServer` we need to apply the 
`quilkin.dev/tokens` annotation to an allocated `GameServer`, with the token content as its value - so let's create 
an allocation, and apply the annotation all in one go!

```shell
$ kubectl create -f ./gameserverallocation.yaml
gameserverallocation.allocation.agones.dev/xonotic-d7rfx-nx7xr created
$ kubectl get gs
NAME                  STATE       ADDRESS         PORT   NODE                               AGE
xonotic-d7rfx-55j7q   Allocated   34.168.170.51   7226   gke-agones-default-534a3f8d-ifpc   23m
xonotic-d7rfx-nx7xr   Ready       34.168.170.51   7984   gke-agones-default-534a3f8d-ifpc   23m
xonotic-d7rfx-sn5d6   Ready       34.168.170.51   7036   gke-agones-default-534a3f8d-ifpc   23m
```

> Don't do this more than once, as then multiple allocated `GameServers` will have the same routing token!

## Connecting Client Side

Instead of connecting to Xonotic or an Agones `GameServer` directly, we'll want to grab the IP and exposed port of 
the `Service` that fronts all our Quilkin proxies:

```shell
$ kubectl get service quilkin-proxies
NAME              TYPE           CLUSTER-IP    EXTERNAL-IP     PORT(S)          AGE
quilkin-proxies   LoadBalancer   10.109.0.12   35.246.94.14    7000:30174/UDP   3h22m
```

We then take the EXTERNAL-IP and port from the `quilkin-proxies` service, and replace the`${LOADBALANCER_IP}` 
with it in `client-token.yaml`. 

Run this configuration locally as:

```shell
$ quilkin -c ./client-token.yaml proxy
{"timestamp":"2022-10-07T22:10:47.257635Z","level":"INFO","fields":{"message":"Starting Quilkin","version":"0.4.0-dev","commit":"c77260a2526542c564829a2c66935c60f00adcd2"},"target":"quilkin::cli"}
{"timestamp":"2022-10-07T22:10:47.258273Z","level":"INFO","fields":{"message":"Starting","port":7000,"proxy_id":"markmandel45"},"target":"quilkin::proxy"}
{"timestamp":"2022-10-07T22:10:47.258321Z","level":"INFO","fields":{"message":"Starting admin endpoint","address":"[::]:9092"},"target":"quilkin::admin"}
{"timestamp":"2022-10-07T22:10:47.258812Z","level":"INFO","fields":{"message":"Quilkin is ready"},"target":"quilkin::proxy"}
```

Now connect to the local client proxy on "127.0.0.1:7000" via the "Multiplayer > Address" field in the
Xonotic client, and Quilkin will take care of appending the routing token to all your UDP packets, which the Quilkin 
proxies will route to the Allocated GameServer, and you can play a gamee! 

...And you didn't have to change the client or the dedicated game server 🤸

## Metrics

The Quilkin instances are also annotated with the 
[appropriate Prometheus annotations](https://github.com/prometheus-community/helm-charts/tree/main/charts/prometheus#scraping-pod-metrics-via-annotations)
to inform Prometheus on how to scrape the Quilkin proxies for metrics.
