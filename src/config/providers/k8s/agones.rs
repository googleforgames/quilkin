/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::net::ToSocketAddrs;
use k8s_openapi::{
    apiextensions_apiserver::pkg::apis::apiextensions::v1::{
        CustomResourceDefinition, CustomResourceDefinitionNames, CustomResourceDefinitionSpec,
        CustomResourceDefinitionVersion, CustomResourceValidation,
    },
    apimachinery::pkg::{apis::meta::v1::ObjectMeta, util::intstr::IntOrString},
};
use kube::{core::Resource, CustomResource};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::endpoint::Endpoint;

const QUILKIN_TOKEN_LABEL: &str = "quilkin.dev/tokens";

/// Auto-generated derived type for GameServerSpec via `CustomResource`
#[derive(Clone, Debug, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GameServer {
    #[schemars(skip)]
    pub metadata: ObjectMeta,
    pub spec: GameServerSpec,
    pub status: Option<GameServerStatus>,
}

#[derive(Clone, Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Inner {
    #[schemars(skip)]
    metadata: ObjectMeta,
    spec: GameServerSpec,
    status: Option<GameServerStatus>,
}

impl<'de> serde::Deserialize<'de> for GameServer {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let value = serde_json::Value::deserialize(de).unwrap();

        serde_json::from_value::<Inner>(value.clone())
            .map_err(|error| {
                tracing::trace!(%error, %value, "gameserver failed");
                Error::custom(error)
            })
            .map(
                |Inner {
                     metadata,
                     spec,
                     status,
                 }| Self {
                    metadata,
                    spec,
                    status,
                },
            )
    }
}

impl GameServer {
    pub fn new(name: &str, spec: GameServerSpec) -> Self {
        Self {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                ..Default::default()
            },
            spec,
            status: None,
        }
    }

    pub fn is_allocated(&self) -> bool {
        self.status.as_ref().map_or(false, |status| {
            tracing::trace!(%status.address, ?status.state, "checking gameserver");
            matches!(status.state, GameServerState::Allocated)
        })
    }
}

impl serde::Serialize for GameServer {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut obj = ser.serialize_struct("GameServer", 5)?;
        obj.serialize_field("apiVersion", &GameServer::api_version(&()))?;
        obj.serialize_field("kind", &GameServer::kind(&()))?;
        obj.serialize_field("metadata", &self.metadata)?;
        obj.serialize_field("spec", &self.spec)?;
        obj.serialize_field("status", &self.status)?;
        obj.end()
    }
}

impl Resource for GameServer {
    type DynamicType = ();
    type Scope = kube::core::NamespaceResourceScope;

    fn group(_: &()) -> std::borrow::Cow<'_, str> {
        "agones.dev".into()
    }

    fn kind(_: &()) -> std::borrow::Cow<'_, str> {
        "GameServer".into()
    }

    fn version(_: &()) -> std::borrow::Cow<'_, str> {
        "v1".into()
    }

    fn api_version(_: &()) -> std::borrow::Cow<'_, str> {
        "agones.dev/v1".into()
    }

    fn plural(_: &()) -> std::borrow::Cow<'_, str> {
        "gameservers".into()
    }

    fn meta(&self) -> &ObjectMeta {
        &self.metadata
    }

    fn meta_mut(&mut self) -> &mut ObjectMeta {
        &mut self.metadata
    }
}

impl kube::core::crd::v1::CustomResourceExt for GameServer {
    fn crd() -> CustomResourceDefinition {
        let open_api_v3_schema = Some(
            schemars::gen::SchemaSettings::openapi3()
                .with(|s| {
                    s.inline_subschemas = true;
                    s.meta_schema = None;
                })
                .with_visitor(kube::core::schema::StructuralSchemaRewriter)
                .into_generator()
                .into_root_schema_for::<Self>(),
        );

        CustomResourceDefinition {
            metadata: ObjectMeta {
                name: Some("gameservers.agones.dev".into()),
                ..<_>::default()
            },
            spec: CustomResourceDefinitionSpec {
                group: "agones.dev".into(),
                scope: "Namespaced".into(),
                names: CustomResourceDefinitionNames {
                    plural: "gameservers".into(),
                    singular: Some("gameserver".into()),
                    kind: "GameServer".into(),
                    ..<_>::default()
                },
                versions: vec![CustomResourceDefinitionVersion {
                    name: "v1".into(),
                    served: true,
                    storage: true,
                    schema: Some(CustomResourceValidation {
                        // Hack to get around k8s and schemars having different
                        // root JSON schema types. Replace this with a From impl
                        open_api_v3_schema: serde_json::from_value(
                            serde_json::to_value(&open_api_v3_schema).unwrap(),
                        )
                        .unwrap(),
                    }),
                    ..<_>::default()
                }],
                ..<_>::default()
            },
            status: None,
        }
    }

    fn crd_name() -> &'static str {
        "gameservers.agones.dev"
    }

    fn api_resource() -> kube::core::dynamic::ApiResource {
        kube::core::dynamic::ApiResource::erase::<Self>(&())
    }

    fn shortnames() -> &'static [&'static str] {
        &[]
    }
}

impl kube::core::object::HasSpec for GameServer {
    type Spec = GameServerSpec;

    fn spec(&self) -> &GameServerSpec {
        &self.spec
    }
    fn spec_mut(&mut self) -> &mut GameServerSpec {
        &mut self.spec
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GameServerSpec {
    /// Container specifies which Pod container is the game server. Only
    /// required if there is more than one container defined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Ports are the array of ports that can be exposed via the game server
    #[serde(default)]
    pub ports: Vec<GameServerPort>,
    /// Configures health checking
    pub health: Health,
    /// Scheduling strategy. Defaults to "Packed"
    pub scheduling: SchedulingStrategy,
    /// Specifies parameters for the Agones SDK Server sidecar container.
    pub sdk_server: SdkServer,
    /// Describes the Pod that will be created for the [`GameServer`].
    pub template: k8s_openapi::api::core::v1::PodTemplateSpec,
}

impl Default for GameServerSpec {
    fn default() -> Self {
        Self {
            container: None,
            ports: vec![],
            health: Default::default(),
            scheduling: SchedulingStrategy::Packed,
            sdk_server: Default::default(),
            template: Default::default(),
        }
    }
}

impl TryFrom<GameServer> for Endpoint {
    type Error = tonic::Status;

    fn try_from(server: GameServer) -> Result<Self, Self::Error> {
        let status = server
            .status
            .as_ref()
            .ok_or_else(|| tonic::Status::internal("No status found for game server"))?;

        let tokens = match server.metadata.annotations.as_ref() {
            Some(annotations) => annotations
                .get(QUILKIN_TOKEN_LABEL)
                .map(|value| {
                    value
                        .split(',')
                        .map(String::from)
                        .map(base64::decode)
                        .filter_map(Result::ok)
                        .collect::<std::collections::BTreeSet<_>>()
                })
                .unwrap_or_default(),
            None => <_>::default(),
        };

        let address = status.address.clone();
        let port = status
            .ports
            .as_ref()
            .and_then(|ports| ports.first().map(|status| status.port))
            .unwrap_or_default();
        let socket_address = (address, port).to_socket_addrs()?.next().unwrap();
        let filter_metadata = crate::endpoint::Metadata { tokens };
        Ok(Self::with_metadata(socket_address.into(), filter_metadata))
    }
}

impl TryFrom<Vec<GameServer>> for crate::endpoint::LocalityEndpoints {
    type Error = tonic::Status;

    fn try_from(servers: Vec<GameServer>) -> Result<Self, Self::Error> {
        Ok(servers
            .into_iter()
            .map(Endpoint::try_from)
            .collect::<Result<std::collections::BTreeSet<_>, _>>()?
            .into())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Health {
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

impl Default for Health {
    fn default() -> Self {
        Self {
            disabled: false,
            period_seconds: default_period_seconds(),
            failure_threshold: default_failure_threshold(),
            initial_delay_seconds: default_failure_threshold(),
        }
    }
}

/// Defines a set of Ports that are to be exposed via the [`GameServer`].
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GameServerPort {
    /// Name is the descriptive name of the port
    pub name: String,
    /// PortPolicy defines the policy for how the HostPort is populated.
    /// Dynamic port will allocate a HostPort within the selected MIN_PORT and MAX_PORT range passed to the controller
    /// at installation time.
    /// When `Static` portPolicy is specified, `HostPort` is required, to specify the port that game clients will
    /// connect to
    #[serde(default)]
    pub port_policy: PortPolicy,
    /// The name of the container on which to open the port. Defaults to the
    /// game server container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// The port that is being opened on the specified container's process
    pub container_port: u16,
    /// The port exposed on the host for clients to connect to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_port: Option<u16>,
    /// Protocol is the network protocol being used. Defaults to UDP. TCP and TCPUDP are other options.
    #[serde(default)]
    pub protocol: Protocol,
}

/// The status for a [`GameServer`] resource.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GameServerStatus {
    /// The current state of a [`GameServer`].
    pub state: GameServerState,
    pub ports: Option<Vec<GameServerStatusPort>>,
    pub address: String,
    pub node_name: String,
    pub reserved_until: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
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
#[serde(rename_all = "camelCase")]
pub struct SdkServer {
    /// LogLevel for SDK server (sidecar) logs. Defaults to "Info"
    #[serde(default)]
    pub log_level: SdkServerLogLevel,
    /// GRPCPort is the port on which the SDK Server binds the gRPC server to accept incoming connections
    #[serde(default = "default_sdk_grpc_port")]
    pub grpc_port: u16,
    /// HTTPPort is the port on which the SDK Server binds the HTTP gRPC gateway server to accept incoming connections
    #[serde(default = "default_sdk_http_port")]
    pub http_port: u16,
}

fn default_sdk_grpc_port() -> u16 {
    9357
}
fn default_sdk_http_port() -> u16 {
    9358
}

impl Default for SdkServer {
    fn default() -> Self {
        Self {
            log_level: Default::default(),
            grpc_port: default_sdk_grpc_port(),
            http_port: default_sdk_http_port(),
        }
    }
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

/// FleetSpec is the spec for a Fleet. More info: <https://agones.dev/site/docs/reference/agones_crd_api_reference/#agones.dev/v1.Fleet>
/// Fleet CRD mostly autogenerated with <https://github.com/kube-rs/kopium>
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema, Default)]
#[kube(
    group = "agones.dev",
    version = "v1",
    kind = "Fleet",
    plural = "fleets"
)]
#[kube(namespaced)]
#[kube(status = "FleetStatus")]
pub struct FleetSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduling: Option<FleetScheduling>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<FleetStrategy>,
    /// GameServer is the data structure for a GameServer resource.
    pub template: GameServerTemplateSpec,
}

/// FleetSpec is the spec for a Fleet. More info: <https://agones.dev/site/docs/reference/agones_crd_api_reference/#agones.dev/v1.Fleet>
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub enum FleetScheduling {
    Packed,
    Distributed,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct FleetStrategy {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "rollingUpdate"
    )]
    pub rolling_update: Option<FleetStrategyRollingUpdate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<FleetStrategyType>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct FleetStrategyRollingUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "maxSurge")]
    pub max_surge: Option<IntOrString>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxUnavailable"
    )]
    pub max_unavailable: Option<IntOrString>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub enum FleetStrategyType {
    Recreate,
    RollingUpdate,
}

/// GameServer is the data structure for a GameServer resource.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, Default)]
pub struct GameServerTemplateSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ObjectMeta>,
    /// GameServerSpec is the spec for a GameServer resource. More info: <https://agones.dev/site/docs/reference/agones_crd_api_reference/#agones.dev/v1.GameServer>
    pub spec: GameServerSpec,
}

/// FleetStatus is the status of a Fleet. More info: <https://agones.dev/site/docs/reference/agones_crd_api_reference/#agones.dev/v1.Fleet>
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct FleetStatus {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "allocatedReplicas"
    )]
    pub allocated_replicas: Option<i64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "readyReplicas"
    )]
    pub ready_replicas: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "reservedReplicas"
    )]
    pub reserved_replicas: Option<i64>,
}
