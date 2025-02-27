use serde::ser::SerializeMap;

use super::*;

impl Config {
    /// Attempts to deserialize `input` as a YAML object representing `Self`.
    pub fn from_reader<R: std::io::Read>(input: R, is_agent: bool) -> Result<Self, eyre::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AllConfig {
            id: Option<String>,
            version: Option<Version>,
            filters: Option<crate::filters::FilterChain>,
            clusters: Option<ClusterMap>,
            datacenters: Option<DatacenterMap>,
            icao_code: Option<IcaoCode>,
            qcmp_port: Option<u16>,
        }

        let cfg: AllConfig = serde_yaml::from_reader(input)?;

        if cfg.datacenters.is_some() && (cfg.icao_code.is_some() || cfg.qcmp_port.is_some()) {
            eyre::bail!("`datacenters` and `icao_code` or `qcmp_port` were present");
        } else if is_agent && cfg.datacenters.is_some() {
            eyre::bail!("`datacenters` was set even though this is an agent");
        }

        let mut typemap = default_typemap();
        if let Some(filters) = cfg.filters {
            typemap.insert::<FilterChain>(Slot::new(filters));
        }
        if let Some(clusters) = cfg.clusters {
            typemap.insert::<ClusterMap>(Watch::new(clusters));
        }
        if let Some(datacenters) = cfg.datacenters {
            typemap.insert::<DatacenterMap>(Watch::new(datacenters));
        } else {
            typemap.insert::<Agent>(Agent {
                icao_code: Slot::new(cfg.icao_code),
                qcmp_port: Slot::new(cfg.qcmp_port),
            });
        }

        Ok(Self {
            dyn_cfg: DynamicConfig {
                id: cfg.id.map_or_else(default_id, Slot::from),
                version: cfg.version.unwrap_or_default(),
                typemap,
            },
        })
    }

    pub fn update_from_json(
        &self,
        map: serde_json::Map<String, serde_json::Value>,
        mut locality: Option<crate::net::endpoint::Locality>,
    ) -> Result<(), eyre::Error> {
        for (k, v) in map {
            match k.as_str() {
                "filters" => {
                    if let Some(filters) = self.dyn_cfg.filters() {
                        filters.try_replace(serde_json::from_value(v)?);
                    }
                }
                "id" => {
                    self.dyn_cfg.id.try_replace(serde_json::from_value(v)?);
                }
                "clusters" => {
                    let Some(clusters) = self.dyn_cfg.clusters() else {
                        continue;
                    };

                    let cmd: cluster::ClusterMapDeser = serde_json::from_value(v)?;
                    tracing::trace!(len = cmd.endpoints.len(), "replacing clusters");
                    clusters.modify(|clusters| {
                        for cluster in cmd.endpoints {
                            clusters.insert(cluster.locality, cluster.endpoints);
                        }

                        if let Some(locality) = locality.take() {
                            clusters.update_unlocated_endpoints(locality);
                        }
                    });
                    self.apply_metrics();
                }
                field => {
                    tracing::debug!(field, "unable to replace invalid field");
                }
            }
        }

        Ok(())
    }
}

impl serde::Serialize for Config {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("version", &self.dyn_cfg.version)?;
        map.serialize_entry("id", &self.dyn_cfg.id)?;
        if let Some(filters) = self.dyn_cfg.filters() {
            map.serialize_entry("filters", filters)?;
        }
        if let Some(clusters) = self.dyn_cfg.clusters() {
            map.serialize_entry("clusters", clusters)?;
        }
        if let Some(datacenters) = self.dyn_cfg.datacenters() {
            map.serialize_entry("datacenters", datacenters)?;
        }
        if let Some(agent) = self.dyn_cfg.agent() {
            map.serialize_entry("icao_code", &agent.icao_code)?;
            map.serialize_entry("qcmp_port", &agent.qcmp_port)?;
        }

        map.end()
    }
}

#[cfg(test)]
mod tests {
    use crate::net::endpoint::{Endpoint, Metadata};
    use serde_json::json;
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn deserialise_client() {
        let config = Config::default_non_agent();
        config.dyn_cfg.clusters().unwrap().modify(|clusters| {
            clusters.insert_default([Endpoint::new("127.0.0.1:25999".parse().unwrap())].into());
        });

        serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn deserialise_server() {
        let config = Config::default_non_agent();
        config.dyn_cfg.clusters().unwrap().modify(|clusters| {
            clusters.insert_default(
                [
                    Endpoint::new("127.0.0.1:26000".parse().unwrap()),
                    Endpoint::new("127.0.0.1:26001".parse().unwrap()),
                ]
                .into(),
            );
        });

        serde_yaml::to_string(&config).unwrap();
    }

    #[test]
    fn parse_default_values() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
             "clusters":[]
        }))
        .unwrap();

        assert!(!config.id().is_empty());
    }

    #[test]
    fn parse_client() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "clusters": [{
                "endpoints": [{
                    "address": "127.0.0.1:25999"
                }],
            }]
        }))
        .unwrap();

        let value = config.dyn_cfg.clusters().unwrap().read();
        assert_eq!(
            &*value,
            &ClusterMap::new_default(
                [Endpoint::new((std::net::Ipv4Addr::LOCALHOST, 25999).into(),)].into()
            )
        );
    }

    #[test]
    fn parse_ipv6_endpoint() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "clusters":[{
                "endpoints": [{
                    "address": "[2345:0425:2CA1:0000:0000:0567:5673:24b5]:25999"
                }],
            }]
        }))
        .unwrap();

        let value = config.dyn_cfg.clusters().unwrap().read();
        assert_eq!(
            &*value,
            &ClusterMap::new_default(
                [Endpoint::new(
                    (
                        "2345:0425:2CA1:0000:0000:0567:5673:24b5"
                            .parse::<Ipv6Addr>()
                            .unwrap(),
                        25999
                    )
                        .into()
                )]
                .into()
            )
        );
    }

    #[test]
    fn parse_server() {
        let config: Config = serde_json::from_value(json!({
            "version": "v1alpha1",
            "clusters": [{
                "endpoints": [
                    {
                        "address" : "127.0.0.1:26000",
                        "metadata": {
                            "quilkin.dev": {
                                "tokens": ["MXg3aWp5Ng==", "OGdqM3YyaQ=="],
                            }
                        }
                    },
                    {
                        "address" : "[2345:0425:2CA1:0000:0000:0567:5673:24b5]:25999",
                        "metadata": {
                            "quilkin.dev": {
                                "tokens": ["bmt1eTcweA=="],
                            }
                        }
                    }
                ],
            }]
        }))
        .unwrap_or_else(|_| Config::default_agent());

        let value = config.dyn_cfg.clusters().unwrap().read();
        assert_eq!(
            &*value,
            &ClusterMap::new_default(
                [
                    Endpoint::with_metadata(
                        "127.0.0.1:26000".parse().unwrap(),
                        Metadata {
                            tokens: vec!["1x7ijy6", "8gj3v2i"]
                                .into_iter()
                                .map(From::from)
                                .collect(),
                        },
                    ),
                    Endpoint::with_metadata(
                        "[2345:0425:2CA1:0000:0000:0567:5673:24b5]:25999"
                            .parse()
                            .unwrap(),
                        Metadata {
                            tokens: vec!["nkuy70x"].into_iter().map(From::from).collect(),
                        },
                    ),
                ]
                .into()
            )
        );
    }

    #[test]
    fn deny_unused_fields() {
        let configs = vec![
            "
version: v1alpha1
foo: bar
clusters:
    - endpoints:
        - address: 127.0.0.1:7001
",
            "
# proxy
version: v1alpha1
foo: bar
id: client-proxy
port: 7000
clusters:
    - endpoints:
        - address: 127.0.0.1:7001
",
            "
# admin
version: v1alpha1
admin:
    foo: bar
    address: 127.0.0.1:7001
",
            "
# static.endpoints
version: v1alpha1
clusters:
    - endpoints:
        - address: 127.0.0.1:7001
          connection_ids:
            - Mxg3aWp5Ng==
",
            "
# static.filters
version: v1alpha1
filters:
  - name: quilkin.core.v1.rate-limiter
    foo: bar
",
            "
# dynamic.management_servers
version: v1alpha1
dynamic:
  management_servers:
    - address: 127.0.0.1:25999
      foo: bar
",
        ];

        for config in configs {
            let result = Config::from_reader(config.as_bytes(), false);
            let error = result.unwrap_err();
            println!("here: {}", error);
            assert!(format!("{error:?}").contains("unknown field"));
        }
    }
}
