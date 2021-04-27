# Using Quilkin

There are two choices for running Quilkin:

* Binary
* Container image

For each version there is both a release version, which is optimised for production usage, and a debug version that 
has debug level logging enabled.

## Binary

The release binary can be downloaded from the 
[Github releases page](https://github.com/googleforgames/quilkin/releases).

Quilkin needs to be run with an accompanying [configuration file](./proxy-configuration.md), like so:

`quilkin --filename="configuration.yaml"`

If you require debug output, you can run the same command can be run with the `quilkin-debug` binary.

You can also use the shorthand of `-f` instead of `--filename` if you so desire.

## Container Image

For each release, there are both a release and debug container image built and hosted on Google Cloud 
[Artifact Registry](https://cloud.google.com/artifact-registry) listed for 
each [release](https://github.com/googleforgames/quilkin/releases).

The production release can be found under the tag: 

`us-docker.pkg.dev/quilkin/release/quilkin:{version}`

Whereas, if you need debugging logging, use the following tag:

`us-docker.pkg.dev/quilkin/release/quilkin:{version}-debug`

Mount your [configuration file](./proxy-configuration.md) at `/etc/quilkin/quilkin.yaml` to configure the Quilkin 
instance inside the container.

A [default configuration](https://github.com/googleforgames/quilkin/blob/examples/agones-sidecar/build/release/quilkin.yaml)
is provided, such the container will start without a new configuration file, but it is configured to point to 
`127.0.0.1:0` as a no-op configuration.

What's next:

* Run through the [netcat with Quilkin quickstart](./quickstart-netcat.md)
* Review our [example integration architectures](./integrations.md)
