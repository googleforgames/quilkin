use crate::config::Filter;
use crate::endpoint::Endpoint;

use prost::Message;
use prost_types::Any;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::xds::{
    config::{
        cluster::v3::{
            cluster::{ClusterDiscoveryType, DiscoveryType},
            Cluster,
        },
        endpoint::v3::{ClusterLoadAssignment, LocalityLbEndpoints},
        listener::v3::{FilterChain, Listener},
    },
    service::discovery::v3::DiscoveryResponse,
    ResourceType,
};

pub struct FileProvider {
    pub path: PathBuf,
}

const DEFAULT_CLUSTER_NAME: &str = "default-quilkin-cluster";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resources {
    filters: Vec<Filter>,
    endpoints: Vec<Endpoint>,
}

impl FileProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    async fn read_config_file(&self) -> Result<Resources, Box<dyn std::error::Error>> {
        let buf = tokio::fs::read(&self.path).await?;
        let config_str: Resources = serde_yaml::from_slice(&buf)?;
        Ok(config_str)
    }

    async fn create_listener_resources(&self, res: &Resources) -> Result<Listener, tonic::Status> {
        let filter_chains = vec![FilterChain {
            filters: res
                .filters
                .clone()
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, crate::filters::Error>>()
                .map_err(|err| tonic::Status::internal(err.to_string()))?,
            ..<_>::default()
        }];

        Ok(Listener {
            filter_chains,
            ..<_>::default()
        })
    }

    async fn create_cluster_resources(&self, res: &Resources) -> Result<Cluster, tonic::Status> {
        let lb_endpoints = res.endpoints.clone().into_iter().map(From::from).collect();
        Ok(Cluster {
            name: DEFAULT_CLUSTER_NAME.into(),
            load_assignment: Some(ClusterLoadAssignment {
                cluster_name: DEFAULT_CLUSTER_NAME.into(),
                endpoints: vec![LocalityLbEndpoints {
                    lb_endpoints,
                    ..<_>::default()
                }],
                ..<_>::default()
            }),
            cluster_discovery_type: Some(ClusterDiscoveryType::Type(DiscoveryType::Static as i32)),
            ..<_>::default()
        })
    }
}

#[tonic::async_trait]
impl crate::xds::DiscoveryServiceProvider for FileProvider {
    async fn discovery_request(
        &self,
        _node_id: &str,
        version: u64,
        kind: ResourceType,
        _names: &[String],
    ) -> Result<DiscoveryResponse, tonic::Status> {
        let rs = self.read_config_file().await.unwrap();
        let cluster = self.create_cluster_resources(&rs).await?;
        let mut buf_cl = Vec::new();
        buf_cl.reserve(cluster.encoded_len());
        cluster.encode(&mut buf_cl).unwrap();

        let listener = self.create_listener_resources(&rs).await?;
        let mut buf_ls = Vec::new();
        buf_ls.reserve(listener.encoded_len());
        listener.encode(&mut buf_ls).unwrap();

        let resp = vec![
            Any {
                type_url: crate::xds::ENDPOINT_TYPE.into(),
                value: buf_cl,
            },
            Any {
                type_url: crate::xds::ENDPOINT_TYPE.into(),
                value: buf_ls,
            },
        ];

        Ok(DiscoveryResponse {
            version_info: version.to_string(),
            resources: resp,
            type_url: kind.type_url().into(),
            ..<_>::default()
        })
    }
}

#[cfg(test)]
mod tests {

    use super::FileProvider;
    use std::fs::File;
    use std::io::Write;
    use tempdir::TempDir;

    use crate::xds::config::{
        cluster::v3::{
            cluster::{ClusterDiscoveryType, DiscoveryType},
            Cluster,
        },
        core::v3::{
            address,
            socket_address::{PortSpecifier, Protocol as SocketProtocol},
            Address, Metadata, SocketAddress,
        },
        endpoint::v3::{
            lb_endpoint::HostIdentifier, ClusterLoadAssignment, Endpoint, LbEndpoint,
            LocalityLbEndpoints,
        },
        listener::v3::{
            filter::ConfigType as LdsConfigType, Filter as EnvoyFilter, FilterChain, Listener,
        },
    };
    use prost_types::Struct;
    use std::collections::{BTreeMap, HashMap};

    const DEFAULT_CLUSTER_NAME: &str = "default-quilkin-cluster";

    #[tokio::test]
    async fn compelete_test() {
        let test_case = r#"
        endpoints:
        - address: 127.0.0.1:4321
          metadata:
            quilkin.dev:
                tokens:
                - MXg3aWp5Ng==
        filters:
        - name: quilkin.filters.firewall.v1alpha1.Firewall
          config:  
            on_read: 
                - action: ALLOW 
                  source: "192.168.75.0/24"
                  ports: 
                    - "10"
            on_write:
                - action: ALLOW 
                  source: "192.168.75.0/24"
                  ports: 
                   - "10"
    "#;

        let tmp_dir = TempDir::new("path").unwrap();
        let tmp_path = tmp_dir.into_path();

        let file_path = tmp_path.join("config.yaml");
        let mut tmp_file = File::create(file_path.clone()).unwrap();
        writeln!(tmp_file, "{}", test_case);

        let fp = FileProvider::new(file_path.clone());
        let rs = fp.read_config_file().await.unwrap();

        let cluster_resource = fp.create_cluster_resources(&rs).await.unwrap();
        let listener_resource = fp.create_listener_resources(&rs).await.unwrap();
        let cluster_envoy = Cluster {
            name: DEFAULT_CLUSTER_NAME.into(),
            load_assignment: Some(ClusterLoadAssignment {
                cluster_name: DEFAULT_CLUSTER_NAME.into(),
                endpoints: vec![LocalityLbEndpoints {
                    lb_endpoints: vec![LbEndpoint {
                        host_identifier: Some(HostIdentifier::Endpoint(Endpoint {
                            address: Some(Address {
                                address: Some(address::Address::SocketAddress(SocketAddress {
                                    protocol: SocketProtocol::Udp as i32,
                                    address: "127.0.0.1".to_string(),
                                    port_specifier: Some(PortSpecifier::PortValue(4321)),
                                    ..<_>::default()
                                })),
                            }),
                            ..<_>::default()
                        })),
                        metadata: Some(Metadata {
                            filter_metadata: HashMap::from([(
                                String::from("quilkin.dev"),
                                Struct {
                                    fields: BTreeMap::from([(
                                        String::from("tokens"),
                                        prost_types::Value {
                                            kind: Some(prost_types::value::Kind::ListValue(
                                                prost_types::ListValue {
                                                    values: "MXg3aWp5Ng=="
                                                        .split(',')
                                                        .map(String::from)
                                                        .map(prost_types::value::Kind::StringValue)
                                                        .map(|kind| prost_types::Value {
                                                            kind: Some(kind),
                                                        })
                                                        .collect::<Vec<_>>(),
                                                },
                                            )),
                                        },
                                    )]),
                                },
                            )]),
                            ..<_>::default()
                        }),
                        ..<_>::default()
                    }],
                    ..<_>::default()
                }],
                ..<_>::default()
            }),
            cluster_discovery_type: Some(ClusterDiscoveryType::Type(DiscoveryType::Static as i32)),
            ..<_>::default()
        };

        let listener_envoy = Listener {
            filter_chains: vec![FilterChain {
                filters: vec![EnvoyFilter {
                    name: "quilkin.filters.firewall.v1alpha1.Firewall".to_string(),
                    config_type: Some(LdsConfigType::TypedConfig(prost_types::Any {
                        type_url: "quilkin.filters.firewall.v1alpha1.Firewall".to_string(),
                        value: vec![
                            10, 23, 18, 15, 49, 57, 50, 46, 49, 54, 56, 46, 55, 53, 46, 48, 47, 50,
                            52, 26, 4, 8, 10, 16, 11, 18, 23, 18, 15, 49, 57, 50, 46, 49, 54, 56,
                            46, 55, 53, 46, 48, 47, 50, 52, 26, 4, 8, 10, 16, 11,
                        ],
                    })),
                    ..<_>::default()
                }],
                ..<_>::default()
            }],
            ..<_>::default()
        };

        assert_eq!(cluster_resource, cluster_envoy);
        assert_eq!(listener_resource, listener_envoy);
    }
}
