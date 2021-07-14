<p  align="center">
    <img src="./docs/logos/logo-white.png" alt="Quilkin logo" height="220">
</p>

![GitHub](https://img.shields.io/github/license/googleforgames/quilkin)
![Crates.io](https://img.shields.io/crates/v/quilkin)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/googleforgames/quilkin)
![GitHub branch checks state](https://img.shields.io/github/checks-status/googleforgames/quilkin/main)
![Discord](https://img.shields.io/discord/773975408265134100)
[![Twitter Follow](https://img.shields.io/twitter/follow/quilkindev?style=social)](https://twitter.com/quilkindev)

Quilkin is a non-transparent UDP proxy specifically designed for use with large scale multiplayer dedicated game servers
deployments, to ensure security, access control, telemetry data, metrics and more.
 
It is designed to be used behind game clients as well as in front of dedicated game servers.

## Project State

Project is currently in *alpha* status, and is being actively developed. Expect things to break.

Not to be used in production systems.

## Usage

* Start with our [Project Overview](./docs/README.md).
* See how to [use Quilkin](./docs/using.md).
* View [example integration architectures](./docs/integrations.md).
* Quickstart: [Quilkin with netcat](docs/quickstart-netcat.md).
* Quickstart: [Quilkin Agones and Xonotic](docs/quickstart-agones-xonotic.md).
* See the [examples](./examples) folder for configuration and usage examples.
* See the [proxy configuration reference](./docs/proxy-configuration.md) for all the configuration options. 
* See the [Session documentation](./docs/session.md) for an overview of quilkin sessions and metrics.
* See [Filter documentation](./docs/extensions/filters/filters.md) for a list of filters, and their configuration options.
* The [Administration interface](./docs/admin.md) provides access to health and metrics endpoints.
* Finally, we also have a [FAQ](./docs/faq.md)
## Code of Conduct

Participation in this project comes under the [Contributor Covenant Code of Conduct](code-of-conduct.md)

## Development and Contribution

Please read the [contributing](CONTRIBUTING.md) guide for directions on writing code and submitting Pull Requests.

Quilkin is in active development - we would love your help in shaping its future!

## Community

There are lots of ways to engage with the Quilkin community:

* Here on [Github](https://github.com/googleforgames/quilkin) via 
  [issues](https://github.com/googleforgames/quilkin/issues) and 
  [pull requests](https://github.com/googleforgames/quilkin/pulls).
* Join our [mailing list](https://groups.google.com/forum/#!forum/quilkin-discuss), which also gives you access to
  our continuous integration builds.
* Join our [Discord chat server](https://discord.gg/mfBNZjBDnc).
* Follow up on [Twitter](https://twitter.com/quilkindev).

## Credits

Many concepts and architectural decisions where inspired by [Envoy Proxy](https://www.envoyproxy.io/). 
Huge thanks to that team for the inspiration they provided with all their hard work. 
 
## Licence

Apache 2.0

<img src="./docs/logos/mascot.png" alt="Quilly, the Quilkin mascot" height="200" align="right">
