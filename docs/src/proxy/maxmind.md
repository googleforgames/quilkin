# ASN Maxmind Information

If Quilkin is provided a
remote URL or local file path to a
Maxmind IP Geolocation database through the `mmdb` [file](../file-configuration.md) or
[command line](../../api/quilkin/cli/struct.Proxy.html#structfield.mmdb)
configuration, Quilkin will log the following information in the `maxmind information` log.

| Field           | Description                                   |
|-----------------|-----------------------------------------------|
| `number`        | ASN Number                                    |
| `organization`  | The organisation responsible for the ASN      |
| `country_code`  | The corresponding country code                |
| `prefix`        | The IP prefix CIDR address                    |
| `prefix_entity` | The name of the entity for the prefix address |
| `prefix_name`   | The name of the prefix address                |

> Maxmind databases often require a licence and/or fee, so they aren't included
> by default with Quilkin.
