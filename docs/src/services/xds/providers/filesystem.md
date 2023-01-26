# Filesystem xDS Provider

The filesystem provider watches a configuration file on disk and sends updates to proxies whenever that file changes.

It can be started with using subcommand `manage file` as the following:
```sh
quilkin manage file quilkin.yaml
```

We run this on port 1800, in this example, in case you are running this locally, and the
default port is taken up by an existing Quilkin proxy.

After running this command, any proxy that connects to port 18000 will receive updates as configured in `config.yaml`
file.

You can find the configuration file schema in [Configuration][configuration].

Example:

```rust
# let yaml = "
version: v1alpha1
filters:
  - name: quilkin.filters.debug.v1alpha1.Debug
    config:
      id: hello
clusters:
  cluster-a:
    localities:
      - endpoints:
          - address: 123.0.0.1:29
            metadata:
              'quilkin.dev':
                tokens:
                  - 'MXg3aWp5Ng=='
# ";
# let config = quilkin::config::Config::from_reader(yaml.as_bytes()).unwrap();
# assert_eq!(config.filters.load().len(), 1);
# quilkin::Proxy::try_from(config).unwrap();
```

[configuration]: ../../../deployment/configuration.md
