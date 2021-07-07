# Overview

Quilkin is a UDP proxy, specifically designed for use with multiplayer dedicated game servers.

## What is Quilkin?

Quilkin on open source is a non-transparent UDP proxy specifically designed for use with large scale multiplayer
dedicated game servers deployments, to ensure security, access control, telemetry data, metrics and more.

It is designed to be used behind game clients as well as in front of dedicated game servers.

Quilkin's aim is to pull the above functionality out of bespoke, monolithic dedicated game servers and clients, and
provide standard, composable modules that can be reused across a wide set of multiplayer games, so that game
developers can instead focus on their game specific aspects of building a multiplayer game.

## Why use Quilkin?

Some of Quilkin's advantages:

* Lower development and operational costs for securing, monitoring and making reliable multiplayer game servers and
  their communications.
* Provide entry-point redundancy for your game clients to connect to - making it much harder to take down your game
  servers.
* Multiple integration patterns, allowing you to choose the level of integration that makes sense for your
  architecture.
* Remove non-game specific computation out of your game server's processing loop - and save that precious CPU for
  your game simulation!

## Major Features

Quilkin incorporates these abilities:

* Non-transparent proxying of UDP data, the internal state of your game architecture is not visible to bad actors.
* Out of the box metrics for UDP packet information.
* Composable tools for access control and security.
* Able to be utilised as a standalone binary, with no client/server changes required or as a Rust library
  depending on how deep an integration you wish for your system.
* Can be integrated with C/C++ code bases via FFI.

## What Next?

* Read the [usage guide](./using.md)
* Have a look at the [example configurations](https://github.com/googleforgames/quilkin/blob/main/examples) for basic configuration examples.
* Check out the [example integration patterns](./integrations.md).
