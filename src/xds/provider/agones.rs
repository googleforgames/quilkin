use prost::Message;
use prost_types::{Any, Struct};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::xds::{
    config::{
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
        listener::v3::{FilterChain, Listener},
    },
    service::discovery::v3::DiscoveryResponse,
    ResourceType,
};

const QUILKIN_CONFIGMAP: &str = "quilkin-config";
const DEFAULT_CLUSTER_NAME: &str = "default-quilkin-cluster";
const QUILKIN_URL: &str = "quilkin.dev";
const QUILKIN_TOKEN_KEY: &str = "tokens";
const QUILKIN_TOKEN_LABEL: &str = "quilkin.dev/tokens";

pub struct AgonesProvider {
    config: kube::Api<k8s_openapi::api::core::v1::ConfigMap>,
    gameservers: kube::Api<GameServer>,
}

impl AgonesProvider {
    #[tracing::instrument(fields(gameservers_namespace = gameservers_namespace.as_ref(), config_namespace = config_namespace.as_ref()))]
    pub async fn new(
        gameservers_namespace: impl AsRef<str>,
        config_namespace: impl AsRef<str>,
    ) -> crate::Result<Self> {
        let client = kube::Client::try_default().await?;
        Ok(Self {
            config: kube::Api::namespaced(client.clone(), config_namespace.as_ref()),
            gameservers: kube::Api::namespaced(client, gameservers_namespace.as_ref()),
        })
    }

    #[tracing::instrument(skip_all)]
    async fn get_listener(&self) -> Result<Listener, tonic::Status> {
        let configmap = self
            .config
            .get(QUILKIN_CONFIGMAP)
            .await
            .map_err(|err| tonic::Status::internal(err.to_string()))?;
        let config = configmap
            .data
            .ok_or_else(|| tonic::Status::internal("No configmap data present"))?;
        let config = config
            .get("quilkin.yaml")
            .ok_or_else(|| tonic::Status::internal("No config.yaml present in configmap."))?;

        #[derive(Clone, Debug, Deserialize, Serialize)]
        struct ConfigData {
            filters: Vec<crate::config::Filter>,
        }

        let data: ConfigData =
            serde_yaml::from_str(config).map_err(|err| tonic::Status::internal(err.to_string()))?;

        let filter_chains = vec![FilterChain {
            filters: data
                .filters
                .into_iter()
                .map(TryFrom::try_from)
                .collect::<Result<_, eyre::Error>>()
                .map_err(|err| tonic::Status::internal(err.to_string()))?,
            ..<_>::default()
        }];

        Ok(Listener {
            filter_chains,
            ..<_>::default()
        })
    }

    #[tracing::instrument(skip_all)]
    async fn get_cluster(&self) -> Result<Cluster, tonic::Status> {
        let lb_endpoints = self
            .gameservers
            .list(&<_>::default())
            .await
            .map_err(|error| tonic::Status::unknown(error.to_string()))?
            .into_iter()
            .filter(|server| server.status.is_some())
            // Only populate with server's that are ready and have a token annotation.
            .filter(|server| {
                let status = server.status.as_ref().unwrap();
                matches!(status.state, GameServerState::Allocated)
                    && !status.address.is_empty()
                    && !status.ports.is_empty()
                    && server
                        .metadata
                        .annotations
                        .as_ref()
                        .map_or(false, |map| map.contains_key(QUILKIN_TOKEN_LABEL))
            })
            .map(|server| {
                let status = server.status.as_ref().unwrap();
                let tokens = server
                    .metadata
                    .annotations
                    .as_ref()
                    .unwrap()
                    .get(QUILKIN_TOKEN_LABEL)
                    .unwrap()
                    .split(',')
                    .map(String::from)
                    .map(prost_types::value::Kind::StringValue)
                    .map(|kind| prost_types::Value { kind: Some(kind) })
                    .collect::<Vec<_>>();

                let tokens = prost_types::Value {
                    kind: Some(prost_types::value::Kind::ListValue(
                        prost_types::ListValue { values: tokens },
                    )),
                };

                LbEndpoint {
                    host_identifier: Some(HostIdentifier::Endpoint(Endpoint {
                        address: Some(Address {
                            address: Some(address::Address::SocketAddress(SocketAddress {
                                protocol: SocketProtocol::Udp as i32,
                                address: status.address.clone(),
                                port_specifier: Some(PortSpecifier::PortValue(
                                    status.ports.first().unwrap().port.into(),
                                )),
                                ..<_>::default()
                            })),
                        }),
                        ..<_>::default()
                    })),
                    metadata: Some(Metadata {
                        filter_metadata: HashMap::from([(
                            String::from(QUILKIN_URL),
                            Struct {
                                fields: BTreeMap::from([(String::from(QUILKIN_TOKEN_KEY), tokens)]),
                            },
                        )]),
                        ..<_>::default()
                    }),
                    ..<_>::default()
                }
            })
            .collect();

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
impl crate::xds::DiscoveryServiceProvider for AgonesProvider {
    #[tracing::instrument(skip_all)]
    async fn discovery_request(
        &self,
        _node_id: &str,
        version: u64,
        kind: ResourceType,
        _names: &[String],
    ) -> Result<DiscoveryResponse, tonic::Status> {
        let value = match kind {
            ResourceType::Endpoint | ResourceType::Cluster => {
                let cluster = self.get_cluster().await?;
                let mut buf = Vec::new();
                buf.reserve(cluster.encoded_len());

                cluster.encode(&mut buf).unwrap();

                buf
            }
            ResourceType::Listener => {
                let listener = self.get_listener().await?;
                let mut buf = Vec::new();
                buf.reserve(listener.encoded_len());

                listener.encode(&mut buf).unwrap();

                buf
            }
            kind => {
                return Err(tonic::Status::internal(format!(
                    "Quilkin currently does not support {} requests",
                    kind.type_url()
                )))
            }
        };

        Ok(DiscoveryResponse {
            version_info: version.to_string(),
            resources: vec![Any {
                type_url: kind.type_url().into(),
                value,
            }],
            type_url: kind.type_url().into(),
            ..<_>::default()
        })
    }
}

#[derive(kube::CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "agones.dev",
    version = "v1",
    kind = "GameServer",
    status = "GameServerStatus",
    namespaced
)]
struct GameServerSpec {
    /// Container specifies which Pod container is the game server. Only
    /// required if there is more than one container defined.
    container: String,
    /// Ports are the array of ports that can be exposed via the game server
    ports: Vec<GameServerPort>,
    /// Configures health checking
    health: Health,
    /// Scheduling strategy. Defaults to "Packed"
    scheduling: SchedulingStrategy,
    /// Specifies parameters for the Agones SDK Server sidecar container.
    #[serde(rename = "sdkServer")]
    sdk_server: SdkServer,
    /// Describes the Pod that will be created for the [`GameServer`].
    template: k8s_openapi::api::core::v1::PodTemplateSpec,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
struct Health {
    /// Whether health checking is disabled or not
    #[serde(default)]
    disabled: bool,
    /// The number of seconds each health ping has to occur in
    #[serde(rename = "periodSeconds", default = "default_period_seconds")]
    period_seconds: i32,
    /// How many failures in a row constitutes unhealthy
    #[serde(rename = "failureThreshold", default = "default_failure_threshold")]
    failure_threshold: i32,
    /// Initial delay before checking health
    #[serde(
        rename = "initialDelaySeconds",
        default = "default_initial_delay_seconds"
    )]
    initial_delay_seconds: i32,
}

fn default_period_seconds() -> i32 {
    5
}
fn default_initial_delay_seconds() -> i32 {
    5
}
fn default_failure_threshold() -> i32 {
    5
}

/// Defines a set of Ports that are to be exposed via the [`GameServer`].
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
struct GameServerPort {
    /// Name is the descriptive name of the port
    name: String,
    /// PortPolicy defines the policy for how the HostPort is populated.
    /// Dynamic port will allocate a HostPort within the selected MIN_PORT and MAX_PORT range passed to the controller
    /// at installation time.
    /// When `Static` portPolicy is specified, `HostPort` is required, to specify the port that game clients will
    /// connect to
    #[serde(rename = "portPolicy", default)]
    port_policy: PortPolicy,
    /// The name of the container on which to open the port. Defaults to the
    /// game server container.
    container: Option<String>,
    /// The port that is being opened on the specified container's process
    #[serde(rename = "containerPort")]
    container_port: u16,
    /// The port exposed on the host for clients to connect to
    #[serde(rename = "hostPort")]
    host_port: Option<u16>,
    /// Protocol is the network protocol being used. Defaults to UDP. TCP and TCPUDP are other options.
    #[serde(default)]
    protocol: Protocol,
}

// GameServerStatus is the status for a GameServer resource
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
struct GameServerStatus {
    /// The current state of a [`GameServer`].
    state: GameServerState,
    ports: Vec<GameServerStatusPort>,
    address: String,
    #[serde(rename = "nodeName")]
    node_name: String,
    #[serde(rename = "reservedUntil")]
    reserved_until: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub enum GameServerState {
    /// A dynamically allocating GameServer is being created, an open port needs
    /// to be allocated
    PortAllocation,
    /// The Pod for the GameServer is being created.
    Creating,
    /// The Pods for the GameServer are being created but are not yet Scheduled
    Starting,
    /// We have determined that the Pod has been scheduled in the cluster --
    /// basically, we have a NodeName
    Scheduled,
    /// The GameServer has declared that it is ready
    RequestReady,
    /// The GameServer is ready to take connections from game clients.
    Ready,
    /// The GameServer has shutdown and everything needs to be deleted from the cluster
    Shutdown,
    /// Something has gone wrong with the Gameserver and it cannot be resolved
    Error,
    /// The GameServer has failed its health checks
    Unhealthy,
    /// The GameServer is reserved and therefore can be allocated but not removed
    Reserved,
    /// The GameServer has been allocated to a session
    Allocated,
}

/// The port that was allocated to a GameServer.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct GameServerStatusPort {
    pub name: String,
    pub port: u16,
}

/// Parameters for the Agones SDK Server sidecar container
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct SdkServer {
    /// LogLevel for SDK server (sidecar) logs. Defaults to "Info"
    #[serde(rename = "logLevel", default)]
    log_level: SdkServerLogLevel,
    /// GRPCPort is the port on which the SDK Server binds the gRPC server to accept incoming connections
    #[serde(rename = "grpcPort", default = "default_sdk_grpc_port")]
    grpc_port: u16,
    /// HTTPPort is the port on which the SDK Server binds the HTTP gRPC gateway server to accept incoming connections
    #[serde(rename = "httpPort", default = "default_sdk_http_port")]
    http_port: u16,
}

fn default_sdk_grpc_port() -> u16 {
    9357
}
fn default_sdk_http_port() -> u16 {
    9358
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub enum SdkServerLogLevel {
    /// Output all messages except for debug messages.
    Info,
    /// Output all messages including debug messages.
    Debug,
    /// Only output error messages.
    Error,
}

impl Default for SdkServerLogLevel {
    fn default() -> Self {
        Self::Info
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub enum PortPolicy {
    /// The user defines the host port to be used in the configuration.
    Static,
    /// The system will choose an open port for the [`GameServer`] in question.
    Dynamic,
    /// Dynamically sets the container port to the same value as the dynamically
    /// selected host port. This will mean that users will need to lookup what
    /// port has been opened through the server side SDK.
    Passthrough,
}

impl Default for PortPolicy {
    fn default() -> Self {
        Self::Dynamic
    }
}

/// the strategy that a Fleet & GameServers will use when scheduling
/// GameServers' Pods across a cluster. In future versions, this will also
/// impact Fleet scale down, and Pod Scheduling.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub enum SchedulingStrategy {
    /// Prioritise allocating GameServers on Nodes with the most Allocated, and
    /// then Ready GameServers to bin pack as many Allocated GameServers on a
    /// single node.  This is most useful for dynamic Kubernetes clusters - such
    /// as on Cloud Providers.
    Packed,
    /// prioritise allocating GameServers on Nodes with the least Allocated, and
    /// then Ready GameServers to distribute Allocated GameServers across many
    /// nodes. This is most useful for statically sized Kubernetes clusters -
    /// such as on physical hardware.
    Distributed,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub enum Protocol {
    #[serde(rename = "UDP")]
    Udp,
    #[serde(rename = "TCP")]
    Tcp,
    #[serde(rename = "TCPUDP")]
    UdpTcp,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Udp
    }
}
