# FAQ

## Just how fast is Quilkin? What sort of performance can I expect?

The project is still in alpha state right now, so no major optimisations for performance have been performed at this 
stage, but for right now it is _fast enough_ for this release.

We plan on working more on performance in upcoming releases, both from an optimisation and observability perspective.

We will always recommend you run your own load tests on your platform and configuration, as performance will always 
change depending on the underlying hardware, number of filters and configurations and more.

## Can I integrate Quilkin with C++ code?

Quilkin is also released as a [library](https://crates.io/crates/quilkin), so it can be integrated with an external 
codebase as necessary.

Using Rust code inside a C or C++ project mostly consists of two parts.

* Creating a C-friendly API in Rust
* Embedding your Rust project into an external build system

See [A little Rust with your C](https://docs.rust-embedded.org/book/interoperability/rust-with-c.html) for more 
information.

Over time, we will be expanding documentation on how to integrate with specific engines if running Quilkin as a 
separate binary is not an option.

## I would like to run Quilkin as a client side proxy on a console? Can I do that?

This is an ongoing discussion, and since console development is protected by non-disclosure agreements, we can't 
comment on this directly.

That being said, we are having discussions on how we can release lean versions of certain filters that would work 
with known supported game engines and languages for circumstances where compiling Rust or a providing a separate 
Quilkin binary as an executable is an option.

## Any reason you didn't contribute this into/extend Envoy?

This is an excellent question! [Envoy](https://www.envoyproxy.io/) is an amazing project, and has set many of the 
standards for how [proxies are written and orchestrated](./xds.md), and was an inspiration for many of 
the decisions made on Quilkin.

However, we decided to build this project separately:

* Envoy seems primarily focused on web/mobile network workloads (which makes total sense), whereas we wanted 
  something specialised on gaming UDP communication, so having a leaner, more focused codebase would allow us to move 
  faster.
* We found the Rust and Cargo ecosystem easier to work with than Bazel and C++, and figured our users would as well.
