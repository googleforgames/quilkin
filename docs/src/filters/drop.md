# Drop

The `Drop` filter always drops any packet passed through it. This is useful in
combination with conditional flow filters like [`Matches`](./match.md)

#### Filter name
```text
quilkin.extensions.filters.drop.v1alpha1.Drop
```

### Configuration Examples
{{#include match.md:example}}

### Configuration

No defined configuration options.

### Metrics

This filter currently exports no metrics.
