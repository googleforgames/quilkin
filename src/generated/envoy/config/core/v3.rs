/// Generic socket option message. This would be used to set socket options that
/// might not exist in upstream kernels or precompiled Envoy binaries.
/// \[#next-free-field: 7\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SocketOption {
    /// An optional name to give this socket option for debugging, etc.
    /// Uniqueness is not required and no special meaning is assumed.
    #[prost(string, tag = "1")]
    pub description: ::prost::alloc::string::String,
    /// Corresponding to the level value passed to setsockopt, such as IPPROTO_TCP
    #[prost(int64, tag = "2")]
    pub level: i64,
    /// The numeric name as passed to setsockopt
    #[prost(int64, tag = "3")]
    pub name: i64,
    /// The state in which the option will be applied. When used in BindConfig
    /// STATE_PREBIND is currently the only valid value.
    #[prost(enumeration = "socket_option::SocketState", tag = "6")]
    pub state: i32,
    #[prost(oneof = "socket_option::Value", tags = "4, 5")]
    pub value: ::core::option::Option<socket_option::Value>,
}
/// Nested message and enum types in `SocketOption`.
pub mod socket_option {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum SocketState {
        /// Socket options are applied after socket creation but before binding the socket to a port
        StatePrebind = 0,
        /// Socket options are applied after binding the socket to a port but before calling listen()
        StateBound = 1,
        /// Socket options are applied after calling listen()
        StateListening = 2,
    }
    impl SocketState {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                SocketState::StatePrebind => "STATE_PREBIND",
                SocketState::StateBound => "STATE_BOUND",
                SocketState::StateListening => "STATE_LISTENING",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "STATE_PREBIND" => Some(Self::StatePrebind),
                "STATE_BOUND" => Some(Self::StateBound),
                "STATE_LISTENING" => Some(Self::StateListening),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        /// Because many sockopts take an int value.
        #[prost(int64, tag = "4")]
        IntValue(i64),
        /// Otherwise it's a byte buffer.
        #[prost(bytes, tag = "5")]
        BufValue(::prost::alloc::vec::Vec<u8>),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Pipe {
    /// Unix Domain Socket path. On Linux, paths starting with '@' will use the
    /// abstract namespace. The starting '@' is replaced by a null byte by Envoy.
    /// Paths starting with '@' will result in an error in environments other than
    /// Linux.
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    /// The mode for the Pipe. Not applicable for abstract sockets.
    #[prost(uint32, tag = "2")]
    pub mode: u32,
}
/// \[#not-implemented-hide:\] The address represents an envoy internal listener.
/// TODO(lambdai): Make this address available for listener and endpoint.
/// TODO(asraa): When address available, remove workaround from test/server/server_fuzz_test.cc:30.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnvoyInternalAddress {
    #[prost(oneof = "envoy_internal_address::AddressNameSpecifier", tags = "1")]
    pub address_name_specifier: ::core::option::Option<
        envoy_internal_address::AddressNameSpecifier,
    >,
}
/// Nested message and enum types in `EnvoyInternalAddress`.
pub mod envoy_internal_address {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum AddressNameSpecifier {
        /// \[#not-implemented-hide:\] The :ref:`listener name <envoy_v3_api_field_config.listener.v3.Listener.name>` of the destination internal listener.
        #[prost(string, tag = "1")]
        ServerListenerName(::prost::alloc::string::String),
    }
}
/// \[#next-free-field: 7\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SocketAddress {
    #[prost(enumeration = "socket_address::Protocol", tag = "1")]
    pub protocol: i32,
    /// The address for this socket. :ref:`Listeners <config_listeners>` will bind
    /// to the address. An empty address is not allowed. Specify ``0.0.0.0`` or ``::``
    /// to bind to any address. [#comment:TODO(zuercher) reinstate when implemented:
    /// It is possible to distinguish a Listener address via the prefix/suffix matching
    /// in :ref:`FilterChainMatch <envoy_v3_api_msg_config.listener.v3.FilterChainMatch>`.] When used
    /// within an upstream :ref:`BindConfig <envoy_v3_api_msg_config.core.v3.BindConfig>`, the address
    /// controls the source address of outbound connections. For :ref:`clusters
    /// <envoy_v3_api_msg_config.cluster.v3.Cluster>`, the cluster type determines whether the
    /// address must be an IP (*STATIC* or *EDS* clusters) or a hostname resolved by DNS
    /// (*STRICT_DNS* or *LOGICAL_DNS* clusters). Address resolution can be customized
    /// via :ref:`resolver_name <envoy_v3_api_field_config.core.v3.SocketAddress.resolver_name>`.
    #[prost(string, tag = "2")]
    pub address: ::prost::alloc::string::String,
    /// The name of the custom resolver. This must have been registered with Envoy. If
    /// this is empty, a context dependent default applies. If the address is a concrete
    /// IP address, no resolution will occur. If address is a hostname this
    /// should be set for resolution other than DNS. Specifying a custom resolver with
    /// *STRICT_DNS* or *LOGICAL_DNS* will generate an error at runtime.
    #[prost(string, tag = "5")]
    pub resolver_name: ::prost::alloc::string::String,
    /// When binding to an IPv6 address above, this enables `IPv4 compatibility
    /// <<https://tools.ietf.org/html/rfc3493#page-11>`_.> Binding to ``::`` will
    /// allow both IPv4 and IPv6 connections, with peer IPv4 addresses mapped into
    /// IPv6 space as ``::FFFF:<IPv4-address>``.
    #[prost(bool, tag = "6")]
    pub ipv4_compat: bool,
    #[prost(oneof = "socket_address::PortSpecifier", tags = "3, 4")]
    pub port_specifier: ::core::option::Option<socket_address::PortSpecifier>,
}
/// Nested message and enum types in `SocketAddress`.
pub mod socket_address {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum Protocol {
        Tcp = 0,
        Udp = 1,
    }
    impl Protocol {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Protocol::Tcp => "TCP",
                Protocol::Udp => "UDP",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "TCP" => Some(Self::Tcp),
                "UDP" => Some(Self::Udp),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum PortSpecifier {
        #[prost(uint32, tag = "3")]
        PortValue(u32),
        /// This is only valid if :ref:`resolver_name
        /// <envoy_v3_api_field_config.core.v3.SocketAddress.resolver_name>` is specified below and the
        /// named resolver is capable of named port resolution.
        #[prost(string, tag = "4")]
        NamedPort(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TcpKeepalive {
    /// Maximum number of keepalive probes to send without response before deciding
    /// the connection is dead. Default is to use the OS level configuration (unless
    /// overridden, Linux defaults to 9.)
    #[prost(message, optional, tag = "1")]
    pub keepalive_probes: ::core::option::Option<u32>,
    /// The number of seconds a connection needs to be idle before keep-alive probes
    /// start being sent. Default is to use the OS level configuration (unless
    /// overridden, Linux defaults to 7200s (i.e., 2 hours.)
    #[prost(message, optional, tag = "2")]
    pub keepalive_time: ::core::option::Option<u32>,
    /// The number of seconds between keep-alive probes. Default is to use the OS
    /// level configuration (unless overridden, Linux defaults to 75s.)
    #[prost(message, optional, tag = "3")]
    pub keepalive_interval: ::core::option::Option<u32>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BindConfig {
    /// The address to bind to when creating a socket.
    #[prost(message, optional, tag = "1")]
    pub source_address: ::core::option::Option<SocketAddress>,
    /// Whether to set the *IP_FREEBIND* option when creating the socket. When this
    /// flag is set to true, allows the :ref:`source_address
    /// <envoy_v3_api_field_config.cluster.v3.UpstreamBindConfig.source_address>` to be an IP address
    /// that is not configured on the system running Envoy. When this flag is set
    /// to false, the option *IP_FREEBIND* is disabled on the socket. When this
    /// flag is not set (default), the socket is not modified, i.e. the option is
    /// neither enabled nor disabled.
    #[prost(message, optional, tag = "2")]
    pub freebind: ::core::option::Option<bool>,
    /// Additional socket options that may not be present in Envoy source code or
    /// precompiled binaries.
    #[prost(message, repeated, tag = "3")]
    pub socket_options: ::prost::alloc::vec::Vec<SocketOption>,
}
/// Addresses specify either a logical or physical address and port, which are
/// used to tell Envoy where to bind/listen, connect to upstream and find
/// management servers.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Address {
    #[prost(oneof = "address::Address", tags = "1, 2, 3")]
    pub address: ::core::option::Option<address::Address>,
}
/// Nested message and enum types in `Address`.
pub mod address {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Address {
        #[prost(message, tag = "1")]
        SocketAddress(super::SocketAddress),
        #[prost(message, tag = "2")]
        Pipe(super::Pipe),
        /// \[#not-implemented-hide:\]
        #[prost(message, tag = "3")]
        EnvoyInternalAddress(super::EnvoyInternalAddress),
    }
}
/// CidrRange specifies an IP Address and a prefix length to construct
/// the subnet mask for a `CIDR <<https://tools.ietf.org/html/rfc4632>`_> range.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CidrRange {
    /// IPv4 or IPv6 address, e.g. ``192.0.0.0`` or ``2001:db8::``.
    #[prost(string, tag = "1")]
    pub address_prefix: ::prost::alloc::string::String,
    /// Length of prefix, e.g. 0, 32. Defaults to 0 when unset.
    #[prost(message, optional, tag = "2")]
    pub prefix_len: ::core::option::Option<u32>,
}
/// Configuration defining a jittered exponential back off strategy.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BackoffStrategy {
    /// The base interval to be used for the next back off computation. It should
    /// be greater than zero and less than or equal to :ref:`max_interval
    /// <envoy_v3_api_field_config.core.v3.BackoffStrategy.max_interval>`.
    #[prost(message, optional, tag = "1")]
    pub base_interval: ::core::option::Option<::prost_types::Duration>,
    /// Specifies the maximum interval between retries. This parameter is optional,
    /// but must be greater than or equal to the :ref:`base_interval
    /// <envoy_v3_api_field_config.core.v3.BackoffStrategy.base_interval>` if set. The default
    /// is 10 times the :ref:`base_interval
    /// <envoy_v3_api_field_config.core.v3.BackoffStrategy.base_interval>`.
    #[prost(message, optional, tag = "2")]
    pub max_interval: ::core::option::Option<::prost_types::Duration>,
}
/// Envoy external URI descriptor
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpUri {
    /// The HTTP server URI. It should be a full FQDN with protocol, host and path.
    ///
    /// Example:
    ///
    /// .. code-block:: yaml
    ///
///```ignore
    ///     uri: <https://www.googleapis.com/oauth2/v1/certs>
///```
    ///
    #[prost(string, tag = "1")]
    pub uri: ::prost::alloc::string::String,
    /// Sets the maximum duration in milliseconds that a response can take to arrive upon request.
    #[prost(message, optional, tag = "3")]
    pub timeout: ::core::option::Option<::prost_types::Duration>,
    /// Specify how `uri` is to be fetched. Today, this requires an explicit
    /// cluster, but in the future we may support dynamic cluster creation or
    /// inline DNS resolution. See `issue
    /// <<https://github.com/envoyproxy/envoy/issues/1606>`_.>
    #[prost(oneof = "http_uri::HttpUpstreamType", tags = "2")]
    pub http_upstream_type: ::core::option::Option<http_uri::HttpUpstreamType>,
}
/// Nested message and enum types in `HttpUri`.
pub mod http_uri {
    /// Specify how `uri` is to be fetched. Today, this requires an explicit
    /// cluster, but in the future we may support dynamic cluster creation or
    /// inline DNS resolution. See `issue
    /// <<https://github.com/envoyproxy/envoy/issues/1606>`_.>
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum HttpUpstreamType {
        /// A cluster is created in the Envoy "cluster_manager" config
        /// section. This field specifies the cluster name.
        ///
        /// Example:
        ///
        /// .. code-block:: yaml
        ///
///```ignore
        ///     cluster: jwks_cluster
///```
        ///
        #[prost(string, tag = "2")]
        Cluster(::prost::alloc::string::String),
    }
}
/// Identifies location of where either Envoy runs or where upstream hosts run.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Locality {
    /// Region this :ref:`zone <envoy_v3_api_field_config.core.v3.Locality.zone>`
    /// belongs to.
    #[prost(string, tag = "1")]
    pub region: ::prost::alloc::string::String,
    /// Defines the local service zone where Envoy is running. Though optional, it
    /// should be set if discovery service routing is used and the discovery
    /// service exposes :ref:`zone data
    /// <envoy_v3_api_field_config.endpoint.v3.LocalityLbEndpoints.locality>`,
    /// either in this message or via :option:`--service-zone`. The meaning of zone
    /// is context dependent, e.g. `Availability Zone (AZ)
    /// <<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html>`_>
    /// on AWS, `Zone <<https://cloud.google.com/compute/docs/regions-zones/>`_> on
    /// GCP, etc.
    #[prost(string, tag = "2")]
    pub zone: ::prost::alloc::string::String,
    /// When used for locality of upstream hosts, this field further splits zone
    /// into smaller chunks of sub-zones so they can be load balanced
    /// independently.
    #[prost(string, tag = "3")]
    pub sub_zone: ::prost::alloc::string::String,
}
/// BuildVersion combines SemVer version of extension with free-form build
/// information (i.e. 'alpha', 'private-build') as a set of strings.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BuildVersion {
    /// SemVer version of extension.
    #[prost(message, optional, tag = "1")]
    pub version: ::core::option::Option<super::super::super::kind::v3::SemanticVersion>,
    /// Free-form build information.
    /// Envoy defines several well known keys in the
    /// source/common/version/version.h file
    #[prost(message, optional, tag = "2")]
    pub metadata: ::core::option::Option<::prost_types::Struct>,
}
/// Version and identification for an Envoy extension.
/// \[#next-free-field: 6\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Extension {
    /// This is the name of the Envoy filter as specified in the Envoy
    /// configuration, e.g. envoy.filters.http.router, com.acme.widget.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Category of the extension.
    /// Extension category names use reverse DNS notation. For instance
    /// "envoy.filters.listener" for Envoy's built-in listener filters or
    /// "com.acme.filters.http" for HTTP filters from acme.com vendor.
    /// [#comment:TODO(yanavlasov): Link to the doc with existing envoy category
    /// names.]
    #[prost(string, tag = "2")]
    pub category: ::prost::alloc::string::String,
    /// \[#not-implemented-hide:\] Type descriptor of extension configuration proto.
    /// [#comment:TODO(yanavlasov): Link to the doc with existing configuration
    /// protos.]
    /// \[#comment:TODO(yanavlasov): Add tests when PR #9391 lands.\]
    #[prost(string, tag = "3")]
    pub type_descriptor: ::prost::alloc::string::String,
    /// The version is a property of the extension and maintained independently
    /// of other extensions and the Envoy API.
    /// This field is not set when extension did not provide version information.
    #[prost(message, optional, tag = "4")]
    pub version: ::core::option::Option<BuildVersion>,
    /// Indicates that the extension is present but was disabled via dynamic
    /// configuration.
    #[prost(bool, tag = "5")]
    pub disabled: bool,
}
/// Identifies a specific Envoy instance. The node identifier is presented to the
/// management server, which may use this identifier to distinguish per Envoy
/// configuration for serving.
/// \[#next-free-field: 13\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Node {
    /// An opaque node identifier for the Envoy node. This also provides the local
    /// service node name. It should be set if any of the following features are
    /// used: :ref:`statsd <arch_overview_statistics>`, :ref:`CDS
    /// <config_cluster_manager_cds>`, and :ref:`HTTP tracing
    /// <arch_overview_tracing>`, either in this message or via
    /// :option:`--service-node`.
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// Defines the local service cluster name where Envoy is running. Though
    /// optional, it should be set if any of the following features are used:
    /// :ref:`statsd <arch_overview_statistics>`, :ref:`health check cluster
    /// verification
    /// <envoy_v3_api_field_config.core.v3.HealthCheck.HttpHealthCheck.service_name_matcher>`,
    /// :ref:`runtime override directory
    /// <envoy_v3_api_msg_config.bootstrap.v3.Runtime>`, :ref:`user agent addition
    /// <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.add_user_agent>`,
    /// :ref:`HTTP global rate limiting <config_http_filters_rate_limit>`,
    /// :ref:`CDS <config_cluster_manager_cds>`, and :ref:`HTTP tracing
    /// <arch_overview_tracing>`, either in this message or via
    /// :option:`--service-cluster`.
    #[prost(string, tag = "2")]
    pub cluster: ::prost::alloc::string::String,
    /// Opaque metadata extending the node identifier. Envoy will pass this
    /// directly to the management server.
    #[prost(message, optional, tag = "3")]
    pub metadata: ::core::option::Option<::prost_types::Struct>,
    /// Map from xDS resource type URL to dynamic context parameters. These may
    /// vary at runtime (unlike other fields in this message). For example, the xDS
    /// client may have a shard identifier that changes during the lifetime of the
    /// xDS client. In Envoy, this would be achieved by updating the dynamic
    /// context on the Server::Instance's LocalInfo context provider. The shard ID
    /// dynamic parameter then appears in this field during future discovery
    /// requests.
    #[prost(map = "string, message", tag = "12")]
    pub dynamic_parameters: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        super::super::super::super::xds::core::v3::ContextParams,
    >,
    /// Locality specifying where the Envoy instance is running.
    #[prost(message, optional, tag = "4")]
    pub locality: ::core::option::Option<Locality>,
    /// Free-form string that identifies the entity requesting config.
    /// E.g. "envoy" or "grpc"
    #[prost(string, tag = "6")]
    pub user_agent_name: ::prost::alloc::string::String,
    /// List of extensions and their versions supported by the node.
    #[prost(message, repeated, tag = "9")]
    pub extensions: ::prost::alloc::vec::Vec<Extension>,
    /// Client feature support list. These are well known features described
    /// in the Envoy API repository for a given major version of an API. Client
    /// features use reverse DNS naming scheme, for example `com.acme.feature`. See
    /// :ref:`the list of features <client_features>` that xDS client may support.
    #[prost(string, repeated, tag = "10")]
    pub client_features: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Known listening ports on the node as a generic hint to the management
    /// server for filtering :ref:`listeners <config_listeners>` to be returned.
    /// For example, if there is a listener bound to port 80, the list can
    /// optionally contain the SocketAddress `(0.0.0.0,80)`. The field is optional
    /// and just a hint.
    #[deprecated]
    #[prost(message, repeated, tag = "11")]
    pub listening_addresses: ::prost::alloc::vec::Vec<Address>,
    #[prost(oneof = "node::UserAgentVersionType", tags = "7, 8")]
    pub user_agent_version_type: ::core::option::Option<node::UserAgentVersionType>,
}
/// Nested message and enum types in `Node`.
pub mod node {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum UserAgentVersionType {
        /// Free-form string that identifies the version of the entity requesting
        /// config. E.g. "1.12.2" or "abcd1234", or "SpecialEnvoyBuild"
        #[prost(string, tag = "7")]
        UserAgentVersion(::prost::alloc::string::String),
        /// Structured version of the entity requesting config.
        #[prost(message, tag = "8")]
        UserAgentBuildVersion(super::BuildVersion),
    }
}
/// Metadata provides additional inputs to filters based on matched listeners,
/// filter chains, routes and endpoints. It is structured as a map, usually from
/// filter name (in reverse DNS format) to metadata specific to the filter.
/// Metadata key-values for a filter are merged as connection and request
/// handling occurs, with later values for the same key overriding earlier
/// values.
///
/// An example use of metadata is providing additional values to
/// http_connection_manager in the envoy.http_connection_manager.access_log
/// namespace.
///
/// Another example use of metadata is to per service config info in cluster
/// metadata, which may get consumed by multiple filters.
///
/// For load balancing, Metadata provides a means to subset cluster endpoints.
/// Endpoints have a Metadata object associated and routes contain a Metadata
/// object to match against. There are some well defined metadata used today for
/// this purpose:
///
/// * ``{"envoy.lb": {"canary": <bool> }}`` This indicates the canary status of
/// an
///```ignore
///    endpoint and is also used during header processing
///    (x-envoy-upstream-canary) and for stats purposes.
///```
/// \[#next-major-version: move to type/metadata/v2\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Metadata {
    /// Key is the reverse DNS filter name, e.g. com.acme.widget. The envoy.*
    /// namespace is reserved for Envoy's built-in filters.
    /// If both *filter_metadata* and
    /// :ref:`typed_filter_metadata
    /// <envoy_v3_api_field_config.core.v3.Metadata.typed_filter_metadata>` fields
    /// are present in the metadata with same keys, only *typed_filter_metadata*
    /// field will be parsed.
    #[prost(map = "string, message", tag = "1")]
    pub filter_metadata: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost_types::Struct,
    >,
    /// Key is the reverse DNS filter name, e.g. com.acme.widget. The envoy.*
    /// namespace is reserved for Envoy's built-in filters.
    /// The value is encoded as google.protobuf.Any.
    /// If both :ref:`filter_metadata
    /// <envoy_v3_api_field_config.core.v3.Metadata.filter_metadata>` and
    /// *typed_filter_metadata* fields are present in the metadata with same keys,
    /// only *typed_filter_metadata* field will be parsed.
    #[prost(map = "string, message", tag = "2")]
    pub typed_filter_metadata: ::std::collections::HashMap<
        ::prost::alloc::string::String,
        ::prost_types::Any,
    >,
}
/// Runtime derived uint32 with a default when not specified.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuntimeUInt32 {
    /// Default value if runtime value is not available.
    #[prost(uint32, tag = "2")]
    pub default_value: u32,
    /// Runtime key to get value for comparison. This value is used if defined.
    #[prost(string, tag = "3")]
    pub runtime_key: ::prost::alloc::string::String,
}
/// Runtime derived percentage with a default when not specified.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuntimePercent {
    /// Default value if runtime value is not available.
    #[prost(message, optional, tag = "1")]
    pub default_value: ::core::option::Option<super::super::super::kind::v3::Percent>,
    /// Runtime key to get value for comparison. This value is used if defined.
    #[prost(string, tag = "2")]
    pub runtime_key: ::prost::alloc::string::String,
}
/// Runtime derived double with a default when not specified.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuntimeDouble {
    /// Default value if runtime value is not available.
    #[prost(double, tag = "1")]
    pub default_value: f64,
    /// Runtime key to get value for comparison. This value is used if defined.
    #[prost(string, tag = "2")]
    pub runtime_key: ::prost::alloc::string::String,
}
/// Runtime derived bool with a default when not specified.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuntimeFeatureFlag {
    /// Default value if runtime value is not available.
    #[prost(message, optional, tag = "1")]
    pub default_value: ::core::option::Option<bool>,
    /// Runtime key to get value for comparison. This value is used if defined. The
    /// boolean value must be represented via its `canonical JSON encoding
    /// <<https://developers.google.com/protocol-buffers/docs/proto3#json>`_.>
    #[prost(string, tag = "2")]
    pub runtime_key: ::prost::alloc::string::String,
}
/// Query parameter name/value pair.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QueryParameter {
    /// The key of the query parameter. Case sensitive.
    #[prost(string, tag = "1")]
    pub key: ::prost::alloc::string::String,
    /// The value of the query parameter.
    #[prost(string, tag = "2")]
    pub value: ::prost::alloc::string::String,
}
/// Header name/value pair.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HeaderValue {
    /// Header name.
    #[prost(string, tag = "1")]
    pub key: ::prost::alloc::string::String,
    /// Header value.
    ///
    /// The same :ref:`format specifier <config_access_log_format>` as used for
    /// :ref:`HTTP access logging <config_access_log>` applies here, however
    /// unknown header values are replaced with the empty string instead of `-`.
    #[prost(string, tag = "2")]
    pub value: ::prost::alloc::string::String,
}
/// Header name/value pair plus option to control append behavior.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HeaderValueOption {
    /// Header name/value pair that this option applies to.
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<HeaderValue>,
    /// Should the value be appended? If true (default), the value is appended to
    /// existing values. Otherwise it replaces any existing values.
    #[prost(message, optional, tag = "2")]
    pub append: ::core::option::Option<bool>,
    /// \[#not-implemented-hide:\] Describes the action taken to append/overwrite the
    /// given value for an existing header or to only add this header if it's
    /// absent. Value defaults to
    /// :ref:`APPEND_IF_EXISTS_OR_ADD<envoy_v3_api_enum_value_config.core.v3.HeaderValueOption.HeaderAppendAction.APPEND_IF_EXISTS_OR_ADD>`.
    #[prost(enumeration = "header_value_option::HeaderAppendAction", tag = "3")]
    pub append_action: i32,
}
/// Nested message and enum types in `HeaderValueOption`.
pub mod header_value_option {
    /// Describes the supported actions types for header append action.
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum HeaderAppendAction {
        /// This action will append the specified value to the existing values if the
        /// header already exists. If the header doesn't exist then this will add the
        /// header with specified key and value.
        AppendIfExistsOrAdd = 0,
        /// This action will add the header if it doesn't already exist. If the
        /// header already exists then this will be a no-op.
        AddIfAbsent = 1,
        /// This action will overwrite the specified value by discarding any existing
        /// values if the header already exists. If the header doesn't exist then
        /// this will add the header with specified key and value.
        OverwriteIfExistsOrAdd = 2,
    }
    impl HeaderAppendAction {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                HeaderAppendAction::AppendIfExistsOrAdd => "APPEND_IF_EXISTS_OR_ADD",
                HeaderAppendAction::AddIfAbsent => "ADD_IF_ABSENT",
                HeaderAppendAction::OverwriteIfExistsOrAdd => {
                    "OVERWRITE_IF_EXISTS_OR_ADD"
                }
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "APPEND_IF_EXISTS_OR_ADD" => Some(Self::AppendIfExistsOrAdd),
                "ADD_IF_ABSENT" => Some(Self::AddIfAbsent),
                "OVERWRITE_IF_EXISTS_OR_ADD" => Some(Self::OverwriteIfExistsOrAdd),
                _ => None,
            }
        }
    }
}
/// Wrapper for a set of headers.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HeaderMap {
    #[prost(message, repeated, tag = "1")]
    pub headers: ::prost::alloc::vec::Vec<HeaderValue>,
}
/// A directory that is watched for changes, e.g. by inotify on Linux.
/// Move/rename events inside this directory trigger the watch.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WatchedDirectory {
    /// Directory path to watch.
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
}
/// Data source consisting of a file, an inline value, or an environment
/// variable.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DataSource {
    #[prost(oneof = "data_source::Specifier", tags = "1, 2, 3, 4")]
    pub specifier: ::core::option::Option<data_source::Specifier>,
}
/// Nested message and enum types in `DataSource`.
pub mod data_source {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Specifier {
        /// Local filesystem data source.
        #[prost(string, tag = "1")]
        Filename(::prost::alloc::string::String),
        /// Bytes inlined in the configuration.
        #[prost(bytes, tag = "2")]
        InlineBytes(::prost::alloc::vec::Vec<u8>),
        /// String inlined in the configuration.
        #[prost(string, tag = "3")]
        InlineString(::prost::alloc::string::String),
        /// Environment variable data source.
        #[prost(string, tag = "4")]
        EnvironmentVariable(::prost::alloc::string::String),
    }
}
/// The message specifies the retry policy of remote data source when fetching
/// fails.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RetryPolicy {
    /// Specifies parameters that control :ref:`retry backoff strategy
    /// <envoy_v3_api_msg_config.core.v3.BackoffStrategy>`. This parameter is
    /// optional, in which case the default base interval is 1000 milliseconds. The
    /// default maximum interval is 10 times the base interval.
    #[prost(message, optional, tag = "1")]
    pub retry_back_off: ::core::option::Option<BackoffStrategy>,
    /// Specifies the allowed number of retries. This parameter is optional and
    /// defaults to 1.
    #[prost(message, optional, tag = "2")]
    pub num_retries: ::core::option::Option<u32>,
}
/// The message specifies how to fetch data from remote and how to verify it.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RemoteDataSource {
    /// The HTTP URI to fetch the remote data.
    #[prost(message, optional, tag = "1")]
    pub http_uri: ::core::option::Option<HttpUri>,
    /// SHA256 string for verifying data.
    #[prost(string, tag = "2")]
    pub sha256: ::prost::alloc::string::String,
    /// Retry policy for fetching remote data.
    #[prost(message, optional, tag = "3")]
    pub retry_policy: ::core::option::Option<RetryPolicy>,
}
/// Async data source which support async data fetch.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AsyncDataSource {
    #[prost(oneof = "async_data_source::Specifier", tags = "1, 2")]
    pub specifier: ::core::option::Option<async_data_source::Specifier>,
}
/// Nested message and enum types in `AsyncDataSource`.
pub mod async_data_source {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Specifier {
        /// Local async data source.
        #[prost(message, tag = "1")]
        Local(super::DataSource),
        /// Remote async data source.
        #[prost(message, tag = "2")]
        Remote(super::RemoteDataSource),
    }
}
/// Configuration for transport socket in :ref:`listeners <config_listeners>` and
/// :ref:`clusters <envoy_v3_api_msg_config.cluster.v3.Cluster>`. If the
/// configuration is empty, a default transport socket implementation and
/// configuration will be chosen based on the platform and existence of
/// tls_context.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransportSocket {
    /// The name of the transport socket to instantiate. The name must match a
    /// supported transport socket implementation.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Implementation specific configuration which depends on the implementation
    /// being instantiated. See the supported transport socket implementations for
    /// further documentation.
    #[prost(oneof = "transport_socket::ConfigType", tags = "3")]
    pub config_type: ::core::option::Option<transport_socket::ConfigType>,
}
/// Nested message and enum types in `TransportSocket`.
pub mod transport_socket {
    /// Implementation specific configuration which depends on the implementation
    /// being instantiated. See the supported transport socket implementations for
    /// further documentation.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ConfigType {
        #[prost(message, tag = "3")]
        TypedConfig(::prost_types::Any),
    }
}
/// Runtime derived FractionalPercent with defaults for when the numerator or
/// denominator is not specified via a runtime key.
///
/// .. note::
///
///```ignore
///    Parsing of the runtime key's data is implemented such that it may be
///    represented as a :ref:`FractionalPercent
///    <envoy_v3_api_msg_type.v3.FractionalPercent>` proto represented as
///    JSON/YAML and may also be represented as an integer with the assumption
///    that the value is an integral percentage out of 100. For instance, a
///    runtime key lookup returning the value "42" would parse as a
///    `FractionalPercent` whose numerator is 42 and denominator is HUNDRED.
///```
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuntimeFractionalPercent {
    /// Default value if the runtime value's for the numerator/denominator keys are
    /// not available.
    #[prost(message, optional, tag = "1")]
    pub default_value: ::core::option::Option<
        super::super::super::kind::v3::FractionalPercent,
    >,
    /// Runtime key for a YAML representation of a FractionalPercent.
    #[prost(string, tag = "2")]
    pub runtime_key: ::prost::alloc::string::String,
}
/// Identifies a specific ControlPlane instance that Envoy is connected to.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ControlPlane {
    /// An opaque control plane identifier that uniquely identifies an instance
    /// of control plane. This can be used to identify which control plane
    /// instance, the Envoy is connected to.
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
}
/// Envoy supports :ref:`upstream priority routing
/// <arch_overview_http_routing_priority>` both at the route and the virtual
/// cluster level. The current priority implementation uses different connection
/// pool and circuit breaking settings for each priority level. This means that
/// even for HTTP/2 requests, two physical connections will be used to an
/// upstream host. In the future Envoy will likely support true HTTP/2 priority
/// over a single upstream connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RoutingPriority {
    Default = 0,
    High = 1,
}
impl RoutingPriority {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            RoutingPriority::Default => "DEFAULT",
            RoutingPriority::High => "HIGH",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "DEFAULT" => Some(Self::Default),
            "HIGH" => Some(Self::High),
            _ => None,
        }
    }
}
/// HTTP request method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RequestMethod {
    MethodUnspecified = 0,
    Get = 1,
    Head = 2,
    Post = 3,
    Put = 4,
    Delete = 5,
    Connect = 6,
    Options = 7,
    Trace = 8,
    Patch = 9,
}
impl RequestMethod {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            RequestMethod::MethodUnspecified => "METHOD_UNSPECIFIED",
            RequestMethod::Get => "GET",
            RequestMethod::Head => "HEAD",
            RequestMethod::Post => "POST",
            RequestMethod::Put => "PUT",
            RequestMethod::Delete => "DELETE",
            RequestMethod::Connect => "CONNECT",
            RequestMethod::Options => "OPTIONS",
            RequestMethod::Trace => "TRACE",
            RequestMethod::Patch => "PATCH",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "METHOD_UNSPECIFIED" => Some(Self::MethodUnspecified),
            "GET" => Some(Self::Get),
            "HEAD" => Some(Self::Head),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "DELETE" => Some(Self::Delete),
            "CONNECT" => Some(Self::Connect),
            "OPTIONS" => Some(Self::Options),
            "TRACE" => Some(Self::Trace),
            "PATCH" => Some(Self::Patch),
            _ => None,
        }
    }
}
/// Identifies the direction of the traffic relative to the local Envoy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum TrafficDirection {
    /// Default option is unspecified.
    Unspecified = 0,
    /// The transport is used for incoming traffic.
    Inbound = 1,
    /// The transport is used for outgoing traffic.
    Outbound = 2,
}
impl TrafficDirection {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            TrafficDirection::Unspecified => "UNSPECIFIED",
            TrafficDirection::Inbound => "INBOUND",
            TrafficDirection::Outbound => "OUTBOUND",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UNSPECIFIED" => Some(Self::Unspecified),
            "INBOUND" => Some(Self::Inbound),
            "OUTBOUND" => Some(Self::Outbound),
            _ => None,
        }
    }
}
/// Message type for extension configuration.
/// \[#next-major-version: revisit all existing typed_config that doesn't use this wrapper.\].
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TypedExtensionConfig {
    /// The name of an extension. This is not used to select the extension, instead
    /// it serves the role of an opaque identifier.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// The typed config for the extension. The type URL will be used to identify
    /// the extension. In the case that the type URL is *xds.type.v3.TypedStruct*
    /// (or, for historical reasons, *udpa.type.v1.TypedStruct*), the inner type
    /// URL of *TypedStruct* will be utilized. See the
    /// :ref:`extension configuration overview
    /// <config_overview_extension_configuration>` for further details.
    #[prost(message, optional, tag = "2")]
    pub typed_config: ::core::option::Option<::prost_types::Any>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProxyProtocolConfig {
    /// The PROXY protocol version to use. See <https://www.haproxy.org/download/2.1/doc/proxy-protocol.txt> for details
    #[prost(enumeration = "proxy_protocol_config::Version", tag = "1")]
    pub version: i32,
}
/// Nested message and enum types in `ProxyProtocolConfig`.
pub mod proxy_protocol_config {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum Version {
        /// PROXY protocol version 1. Human readable format.
        V1 = 0,
        /// PROXY protocol version 2. Binary format.
        V2 = 1,
    }
    impl Version {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Version::V1 => "V1",
                Version::V2 => "V2",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "V1" => Some(Self::V1),
                "V2" => Some(Self::V2),
                _ => None,
            }
        }
    }
}
/// gRPC service configuration. This is used by :ref:`ApiConfigSource
/// <envoy_v3_api_msg_config.core.v3.ApiConfigSource>` and filter configurations.
/// \[#next-free-field: 6\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GrpcService {
    /// The timeout for the gRPC request. This is the timeout for a specific
    /// request.
    #[prost(message, optional, tag = "3")]
    pub timeout: ::core::option::Option<::prost_types::Duration>,
    /// Additional metadata to include in streams initiated to the GrpcService. This can be used for
    /// scenarios in which additional ad hoc authorization headers (e.g. ``x-foo-bar: baz-key``) are to
    /// be injected. For more information, including details on header value syntax, see the
    /// documentation on :ref:`custom request headers
    /// <config_http_conn_man_headers_custom_request_headers>`.
    #[prost(message, repeated, tag = "5")]
    pub initial_metadata: ::prost::alloc::vec::Vec<HeaderValue>,
    #[prost(oneof = "grpc_service::TargetSpecifier", tags = "1, 2")]
    pub target_specifier: ::core::option::Option<grpc_service::TargetSpecifier>,
}
/// Nested message and enum types in `GrpcService`.
pub mod grpc_service {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct EnvoyGrpc {
        /// The name of the upstream gRPC cluster. SSL credentials will be supplied
        /// in the :ref:`Cluster <envoy_v3_api_msg_config.cluster.v3.Cluster>` :ref:`transport_socket
        /// <envoy_v3_api_field_config.cluster.v3.Cluster.transport_socket>`.
        #[prost(string, tag = "1")]
        pub cluster_name: ::prost::alloc::string::String,
        /// The `:authority` header in the grpc request. If this field is not set, the authority header value will be `cluster_name`.
        /// Note that this authority does not override the SNI. The SNI is provided by the transport socket of the cluster.
        #[prost(string, tag = "2")]
        pub authority: ::prost::alloc::string::String,
    }
    /// \[#next-free-field: 9\]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GoogleGrpc {
        /// The target URI when using the `Google C++ gRPC client
        /// <<https://github.com/grpc/grpc>`_.> SSL credentials will be supplied in
        /// :ref:`channel_credentials <envoy_v3_api_field_config.core.v3.GrpcService.GoogleGrpc.channel_credentials>`.
        #[prost(string, tag = "1")]
        pub target_uri: ::prost::alloc::string::String,
        #[prost(message, optional, tag = "2")]
        pub channel_credentials: ::core::option::Option<google_grpc::ChannelCredentials>,
        /// A set of call credentials that can be composed with `channel credentials
        /// <<https://grpc.io/docs/guides/auth.html#credential-types>`_.>
        #[prost(message, repeated, tag = "3")]
        pub call_credentials: ::prost::alloc::vec::Vec<google_grpc::CallCredentials>,
        /// The human readable prefix to use when emitting statistics for the gRPC
        /// service.
        ///
        /// .. csv-table::
///```ignore
        ///     :header: Name, Type, Description
        ///     :widths: 1, 1, 2
///```
        ///
///```ignore
        ///     streams_total, Counter, Total number of streams opened
        ///     streams_closed_<gRPC status code>, Counter, Total streams closed with <gRPC status code>
///```
        #[prost(string, tag = "4")]
        pub stat_prefix: ::prost::alloc::string::String,
        /// The name of the Google gRPC credentials factory to use. This must have been registered with
        /// Envoy. If this is empty, a default credentials factory will be used that sets up channel
        /// credentials based on other configuration parameters.
        #[prost(string, tag = "5")]
        pub credentials_factory_name: ::prost::alloc::string::String,
        /// Additional configuration for site-specific customizations of the Google
        /// gRPC library.
        #[prost(message, optional, tag = "6")]
        pub config: ::core::option::Option<::prost_types::Struct>,
        /// How many bytes each stream can buffer internally.
        /// If not set an implementation defined default is applied (1MiB).
        #[prost(message, optional, tag = "7")]
        pub per_stream_buffer_limit_bytes: ::core::option::Option<u32>,
        /// Custom channels args.
        #[prost(message, optional, tag = "8")]
        pub channel_args: ::core::option::Option<google_grpc::ChannelArgs>,
    }
    /// Nested message and enum types in `GoogleGrpc`.
    pub mod google_grpc {
        /// See <https://grpc.io/grpc/cpp/structgrpc_1_1_ssl_credentials_options.html.>
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct SslCredentials {
            /// PEM encoded server root certificates.
            #[prost(message, optional, tag = "1")]
            pub root_certs: ::core::option::Option<super::super::DataSource>,
            /// PEM encoded client private key.
            #[prost(message, optional, tag = "2")]
            pub private_key: ::core::option::Option<super::super::DataSource>,
            /// PEM encoded client certificate chain.
            #[prost(message, optional, tag = "3")]
            pub cert_chain: ::core::option::Option<super::super::DataSource>,
        }
        /// Local channel credentials. Only UDS is supported for now.
        /// See <https://github.com/grpc/grpc/pull/15909.>
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct GoogleLocalCredentials {}
        /// See <https://grpc.io/docs/guides/auth.html#credential-types> to understand Channel and Call
        /// credential types.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ChannelCredentials {
            #[prost(
                oneof = "channel_credentials::CredentialSpecifier",
                tags = "1, 2, 3"
            )]
            pub credential_specifier: ::core::option::Option<
                channel_credentials::CredentialSpecifier,
            >,
        }
        /// Nested message and enum types in `ChannelCredentials`.
        pub mod channel_credentials {
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum CredentialSpecifier {
                #[prost(message, tag = "1")]
                SslCredentials(super::SslCredentials),
                /// <https://grpc.io/grpc/cpp/namespacegrpc.html#a6beb3ac70ff94bd2ebbd89b8f21d1f61>
                #[prost(message, tag = "2")]
                GoogleDefault(()),
                #[prost(message, tag = "3")]
                LocalCredentials(super::GoogleLocalCredentials),
            }
        }
        /// \[#next-free-field: 8\]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct CallCredentials {
            #[prost(
                oneof = "call_credentials::CredentialSpecifier",
                tags = "1, 2, 3, 4, 5, 6, 7"
            )]
            pub credential_specifier: ::core::option::Option<
                call_credentials::CredentialSpecifier,
            >,
        }
        /// Nested message and enum types in `CallCredentials`.
        pub mod call_credentials {
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct ServiceAccountJwtAccessCredentials {
                #[prost(string, tag = "1")]
                pub json_key: ::prost::alloc::string::String,
                #[prost(uint64, tag = "2")]
                pub token_lifetime_seconds: u64,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct GoogleIamCredentials {
                #[prost(string, tag = "1")]
                pub authorization_token: ::prost::alloc::string::String,
                #[prost(string, tag = "2")]
                pub authority_selector: ::prost::alloc::string::String,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct MetadataCredentialsFromPlugin {
                #[prost(string, tag = "1")]
                pub name: ::prost::alloc::string::String,
                /// \[#extension-category: envoy.grpc_credentials\]
                #[prost(
                    oneof = "metadata_credentials_from_plugin::ConfigType",
                    tags = "3"
                )]
                pub config_type: ::core::option::Option<
                    metadata_credentials_from_plugin::ConfigType,
                >,
            }
            /// Nested message and enum types in `MetadataCredentialsFromPlugin`.
            pub mod metadata_credentials_from_plugin {
                /// \[#extension-category: envoy.grpc_credentials\]
                #[allow(clippy::derive_partial_eq_without_eq)]
                #[derive(Clone, PartialEq, ::prost::Oneof)]
                pub enum ConfigType {
                    #[prost(message, tag = "3")]
                    TypedConfig(::prost_types::Any),
                }
            }
            /// Security token service configuration that allows Google gRPC to
            /// fetch security token from an OAuth 2.0 authorization server.
            /// See <https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16> and
            /// <https://github.com/grpc/grpc/pull/19587.>
            /// \[#next-free-field: 10\]
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct StsService {
                /// URI of the token exchange service that handles token exchange requests.
                /// [#comment:TODO(asraa): Add URI validation when implemented. Tracked by
                /// <https://github.com/envoyproxy/protoc-gen-validate/issues/303]>
                #[prost(string, tag = "1")]
                pub token_exchange_service_uri: ::prost::alloc::string::String,
                /// Location of the target service or resource where the client
                /// intends to use the requested security token.
                #[prost(string, tag = "2")]
                pub resource: ::prost::alloc::string::String,
                /// Logical name of the target service where the client intends to
                /// use the requested security token.
                #[prost(string, tag = "3")]
                pub audience: ::prost::alloc::string::String,
                /// The desired scope of the requested security token in the
                /// context of the service or resource where the token will be used.
                #[prost(string, tag = "4")]
                pub scope: ::prost::alloc::string::String,
                /// Type of the requested security token.
                #[prost(string, tag = "5")]
                pub requested_token_type: ::prost::alloc::string::String,
                /// The path of subject token, a security token that represents the
                /// identity of the party on behalf of whom the request is being made.
                #[prost(string, tag = "6")]
                pub subject_token_path: ::prost::alloc::string::String,
                /// Type of the subject token.
                #[prost(string, tag = "7")]
                pub subject_token_type: ::prost::alloc::string::String,
                /// The path of actor token, a security token that represents the identity
                /// of the acting party. The acting party is authorized to use the
                /// requested security token and act on behalf of the subject.
                #[prost(string, tag = "8")]
                pub actor_token_path: ::prost::alloc::string::String,
                /// Type of the actor token.
                #[prost(string, tag = "9")]
                pub actor_token_type: ::prost::alloc::string::String,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum CredentialSpecifier {
                /// Access token credentials.
                /// <https://grpc.io/grpc/cpp/namespacegrpc.html#ad3a80da696ffdaea943f0f858d7a360d.>
                #[prost(string, tag = "1")]
                AccessToken(::prost::alloc::string::String),
                /// Google Compute Engine credentials.
                /// <https://grpc.io/grpc/cpp/namespacegrpc.html#a6beb3ac70ff94bd2ebbd89b8f21d1f61>
                #[prost(message, tag = "2")]
                GoogleComputeEngine(()),
                /// Google refresh token credentials.
                /// <https://grpc.io/grpc/cpp/namespacegrpc.html#a96901c997b91bc6513b08491e0dca37c.>
                #[prost(string, tag = "3")]
                GoogleRefreshToken(::prost::alloc::string::String),
                /// Service Account JWT Access credentials.
                /// <https://grpc.io/grpc/cpp/namespacegrpc.html#a92a9f959d6102461f66ee973d8e9d3aa.>
                #[prost(message, tag = "4")]
                ServiceAccountJwtAccess(ServiceAccountJwtAccessCredentials),
                /// Google IAM credentials.
                /// <https://grpc.io/grpc/cpp/namespacegrpc.html#a9fc1fc101b41e680d47028166e76f9d0.>
                #[prost(message, tag = "5")]
                GoogleIam(GoogleIamCredentials),
                /// Custom authenticator credentials.
                /// <https://grpc.io/grpc/cpp/namespacegrpc.html#a823c6a4b19ffc71fb33e90154ee2ad07.>
                /// <https://grpc.io/docs/guides/auth.html#extending-grpc-to-support-other-authentication-mechanisms.>
                #[prost(message, tag = "6")]
                FromPlugin(MetadataCredentialsFromPlugin),
                /// Custom security token service which implements OAuth 2.0 token exchange.
                /// <https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-16>
                /// See <https://github.com/grpc/grpc/pull/19587.>
                #[prost(message, tag = "7")]
                StsService(StsService),
            }
        }
        /// Channel arguments.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ChannelArgs {
            /// See grpc_types.h GRPC_ARG #defines for keys that work here.
            #[prost(map = "string, message", tag = "1")]
            pub args: ::std::collections::HashMap<
                ::prost::alloc::string::String,
                channel_args::Value,
            >,
        }
        /// Nested message and enum types in `ChannelArgs`.
        pub mod channel_args {
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct Value {
                /// Pointer values are not supported, since they don't make any sense when
                /// delivered via the API.
                #[prost(oneof = "value::ValueSpecifier", tags = "1, 2")]
                pub value_specifier: ::core::option::Option<value::ValueSpecifier>,
            }
            /// Nested message and enum types in `Value`.
            pub mod value {
                /// Pointer values are not supported, since they don't make any sense when
                /// delivered via the API.
                #[allow(clippy::derive_partial_eq_without_eq)]
                #[derive(Clone, PartialEq, ::prost::Oneof)]
                pub enum ValueSpecifier {
                    #[prost(string, tag = "1")]
                    StringValue(::prost::alloc::string::String),
                    #[prost(int64, tag = "2")]
                    IntValue(i64),
                }
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum TargetSpecifier {
        /// Envoy's in-built gRPC client.
        /// See the :ref:`gRPC services overview <arch_overview_grpc_services>`
        /// documentation for discussion on gRPC client selection.
        #[prost(message, tag = "1")]
        EnvoyGrpc(EnvoyGrpc),
        /// `Google C++ gRPC client <<https://github.com/grpc/grpc>`_>
        /// See the :ref:`gRPC services overview <arch_overview_grpc_services>`
        /// documentation for discussion on gRPC client selection.
        #[prost(message, tag = "2")]
        GoogleGrpc(GoogleGrpc),
    }
}
/// API configuration source. This identifies the API type and cluster that Envoy
/// will use to fetch an xDS API.
/// \[#next-free-field: 10\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApiConfigSource {
    /// API type (gRPC, REST, delta gRPC)
    #[prost(enumeration = "api_config_source::ApiType", tag = "1")]
    pub api_type: i32,
    /// API version for xDS transport protocol. This describes the xDS gRPC/REST
    /// endpoint and version of \[Delta\]DiscoveryRequest/Response used on the wire.
    #[prost(enumeration = "ApiVersion", tag = "8")]
    pub transport_api_version: i32,
    /// Cluster names should be used only with REST. If > 1
    /// cluster is defined, clusters will be cycled through if any kind of failure
    /// occurs.
    ///
    /// .. note::
    ///
    ///   The cluster with name ``cluster_name`` must be statically defined and its
    ///   type must not be ``EDS``.
    #[prost(string, repeated, tag = "2")]
    pub cluster_names: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Multiple gRPC services be provided for GRPC. If > 1 cluster is defined,
    /// services will be cycled through if any kind of failure occurs.
    #[prost(message, repeated, tag = "4")]
    pub grpc_services: ::prost::alloc::vec::Vec<GrpcService>,
    /// For REST APIs, the delay between successive polls.
    #[prost(message, optional, tag = "3")]
    pub refresh_delay: ::core::option::Option<::prost_types::Duration>,
    /// For REST APIs, the request timeout. If not set, a default value of 1s will be used.
    #[prost(message, optional, tag = "5")]
    pub request_timeout: ::core::option::Option<::prost_types::Duration>,
    /// For GRPC APIs, the rate limit settings. If present, discovery requests made by Envoy will be
    /// rate limited.
    #[prost(message, optional, tag = "6")]
    pub rate_limit_settings: ::core::option::Option<RateLimitSettings>,
    /// Skip the node identifier in subsequent discovery requests for streaming gRPC config types.
    #[prost(bool, tag = "7")]
    pub set_node_on_first_message_only: bool,
    /// A list of config validators that will be executed when a new update is
    /// received from the ApiConfigSource. Note that each validator handles a
    /// specific xDS service type, and only the validators corresponding to the
    /// type url (in `:ref: DiscoveryResponse` or `:ref: DeltaDiscoveryResponse`)
    /// will be invoked.
    /// If the validator returns false or throws an exception, the config will be rejected by
    /// the client, and a NACK will be sent.
    /// \[#extension-category: envoy.config.validators\]
    #[prost(message, repeated, tag = "9")]
    pub config_validators: ::prost::alloc::vec::Vec<TypedExtensionConfig>,
}
/// Nested message and enum types in `ApiConfigSource`.
pub mod api_config_source {
    /// APIs may be fetched via either REST or gRPC.
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum ApiType {
        /// Ideally this would be 'reserved 0' but one can't reserve the default
        /// value. Instead we throw an exception if this is ever used.
        DeprecatedAndUnavailableDoNotUse = 0,
        /// REST-JSON v2 API. The `canonical JSON encoding
        /// <<https://developers.google.com/protocol-buffers/docs/proto3#json>`_> for
        /// the v2 protos is used.
        Rest = 1,
        /// SotW gRPC service.
        Grpc = 2,
        /// Using the delta xDS gRPC service, i.e. DeltaDiscovery{Request,Response}
        /// rather than Discovery{Request,Response}. Rather than sending Envoy the entire state
        /// with every update, the xDS server only sends what has changed since the last update.
        DeltaGrpc = 3,
        /// SotW xDS gRPC with ADS. All resources which resolve to this configuration source will be
        /// multiplexed on a single connection to an ADS endpoint.
        /// \[#not-implemented-hide:\]
        AggregatedGrpc = 5,
        /// Delta xDS gRPC with ADS. All resources which resolve to this configuration source will be
        /// multiplexed on a single connection to an ADS endpoint.
        /// \[#not-implemented-hide:\]
        AggregatedDeltaGrpc = 6,
    }
    impl ApiType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ApiType::DeprecatedAndUnavailableDoNotUse => {
                    "DEPRECATED_AND_UNAVAILABLE_DO_NOT_USE"
                }
                ApiType::Rest => "REST",
                ApiType::Grpc => "GRPC",
                ApiType::DeltaGrpc => "DELTA_GRPC",
                ApiType::AggregatedGrpc => "AGGREGATED_GRPC",
                ApiType::AggregatedDeltaGrpc => "AGGREGATED_DELTA_GRPC",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "DEPRECATED_AND_UNAVAILABLE_DO_NOT_USE" => {
                    Some(Self::DeprecatedAndUnavailableDoNotUse)
                }
                "REST" => Some(Self::Rest),
                "GRPC" => Some(Self::Grpc),
                "DELTA_GRPC" => Some(Self::DeltaGrpc),
                "AGGREGATED_GRPC" => Some(Self::AggregatedGrpc),
                "AGGREGATED_DELTA_GRPC" => Some(Self::AggregatedDeltaGrpc),
                _ => None,
            }
        }
    }
}
/// Aggregated Discovery Service (ADS) options. This is currently empty, but when
/// set in :ref:`ConfigSource <envoy_v3_api_msg_config.core.v3.ConfigSource>` can be used to
/// specify that ADS is to be used.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AggregatedConfigSource {}
/// \[#not-implemented-hide:\]
/// Self-referencing config source options. This is currently empty, but when
/// set in :ref:`ConfigSource <envoy_v3_api_msg_config.core.v3.ConfigSource>` can be used to
/// specify that other data can be obtained from the same server.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SelfConfigSource {
    /// API version for xDS transport protocol. This describes the xDS gRPC/REST
    /// endpoint and version of \[Delta\]DiscoveryRequest/Response used on the wire.
    #[prost(enumeration = "ApiVersion", tag = "1")]
    pub transport_api_version: i32,
}
/// Rate Limit settings to be applied for discovery requests made by Envoy.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RateLimitSettings {
    /// Maximum number of tokens to be used for rate limiting discovery request calls. If not set, a
    /// default value of 100 will be used.
    #[prost(message, optional, tag = "1")]
    pub max_tokens: ::core::option::Option<u32>,
    /// Rate at which tokens will be filled per second. If not set, a default fill rate of 10 tokens
    /// per second will be used.
    #[prost(message, optional, tag = "2")]
    pub fill_rate: ::core::option::Option<f64>,
}
/// Local filesystem path configuration source.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PathConfigSource {
    /// Path on the filesystem to source and watch for configuration updates.
    /// When sourcing configuration for a :ref:`secret <envoy_v3_api_msg_extensions.transport_sockets.tls.v3.Secret>`,
    /// the certificate and key files are also watched for updates.
    ///
    /// .. note::
    ///
    ///   The path to the source must exist at config load time.
    ///
    /// .. note::
    ///
///```ignore
    ///    If `watched_directory` is *not* configured, Envoy will watch the file path for *moves.*
    ///    This is because in general only moves are atomic. The same method of swapping files as is
    ///    demonstrated in the :ref:`runtime documentation <config_runtime_symbolic_link_swap>` can be
    ///    used here also. If `watched_directory` is configured, no watch will be placed directly on
    ///    this path. Instead, the configured `watched_directory` will be used to trigger reloads of
    ///    this path. This is required in certain deployment scenarios. See below for more information.
///```
    #[prost(string, tag = "1")]
    pub path: ::prost::alloc::string::String,
    /// If configured, this directory will be watched for *moves.* When an entry in this directory is
    /// moved to, the `path` will be reloaded. This is required in certain deployment scenarios.
    ///
    /// Specifically, if trying to load an xDS resource using a
    /// `Kubernetes ConfigMap <<https://kubernetes.io/docs/concepts/configuration/configmap/>`_,> the
    /// following configuration might be used:
    /// 1. Store xds.yaml inside a ConfigMap.
    /// 2. Mount the ConfigMap to `/config_map/xds`
    /// 3. Configure path `/config_map/xds/xds.yaml`
    /// 4. Configure watched directory `/config_map/xds`
    ///
    /// The above configuration will ensure that Envoy watches the owning directory for moves which is
    /// required due to how Kubernetes manages ConfigMap symbolic links during atomic updates.
    #[prost(message, optional, tag = "2")]
    pub watched_directory: ::core::option::Option<WatchedDirectory>,
}
/// Configuration for :ref:`listeners <config_listeners>`, :ref:`clusters
/// <config_cluster_manager>`, :ref:`routes
/// <envoy_v3_api_msg_config.route.v3.RouteConfiguration>`, :ref:`endpoints
/// <arch_overview_service_discovery>` etc. may either be sourced from the
/// filesystem or from an xDS API source. Filesystem configs are watched with
/// inotify for updates.
/// \[#next-free-field: 9\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConfigSource {
    /// Authorities that this config source may be used for. An authority specified in a xdstp:// URL
    /// is resolved to a *ConfigSource* prior to configuration fetch. This field provides the
    /// association between authority name and configuration source.
    /// \[#not-implemented-hide:\]
    #[prost(message, repeated, tag = "7")]
    pub authorities: ::prost::alloc::vec::Vec<
        super::super::super::super::xds::core::v3::Authority,
    >,
    /// When this timeout is specified, Envoy will wait no longer than the specified time for first
    /// config response on this xDS subscription during the :ref:`initialization process
    /// <arch_overview_initialization>`. After reaching the timeout, Envoy will move to the next
    /// initialization phase, even if the first config is not delivered yet. The timer is activated
    /// when the xDS API subscription starts, and is disarmed on first config update or on error. 0
    /// means no timeout - Envoy will wait indefinitely for the first xDS config (unless another
    /// timeout applies). The default is 15s.
    #[prost(message, optional, tag = "4")]
    pub initial_fetch_timeout: ::core::option::Option<::prost_types::Duration>,
    /// API version for xDS resources. This implies the type URLs that the client
    /// will request for resources and the resource type that the client will in
    /// turn expect to be delivered.
    #[prost(enumeration = "ApiVersion", tag = "6")]
    pub resource_api_version: i32,
    #[prost(oneof = "config_source::ConfigSourceSpecifier", tags = "1, 8, 2, 3, 5")]
    pub config_source_specifier: ::core::option::Option<
        config_source::ConfigSourceSpecifier,
    >,
}
/// Nested message and enum types in `ConfigSource`.
pub mod config_source {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ConfigSourceSpecifier {
        /// Deprecated in favor of `path_config_source`. Use that field instead.
        #[prost(string, tag = "1")]
        Path(::prost::alloc::string::String),
        /// Local filesystem path configuration source.
        #[prost(message, tag = "8")]
        PathConfigSource(super::PathConfigSource),
        /// API configuration source.
        #[prost(message, tag = "2")]
        ApiConfigSource(super::ApiConfigSource),
        /// When set, ADS will be used to fetch resources. The ADS API configuration
        /// source in the bootstrap configuration is used.
        #[prost(message, tag = "3")]
        Ads(super::AggregatedConfigSource),
        /// \[#not-implemented-hide:\]
        /// When set, the client will access the resources from the same server it got the
        /// ConfigSource from, although not necessarily from the same stream. This is similar to the
        /// :ref:`ads<envoy_v3_api_field.ConfigSource.ads>` field, except that the client may use a
        /// different stream to the same server. As a result, this field can be used for things
        /// like LRS that cannot be sent on an ADS stream. It can also be used to link from (e.g.)
        /// LDS to RDS on the same server without requiring the management server to know its name
        /// or required credentials.
        /// [#next-major-version: In xDS v3, consider replacing the ads field with this one, since
        /// this field can implicitly mean to use the same stream in the case where the ConfigSource
        /// is provided via ADS and the specified data can also be obtained via ADS.]
        #[prost(message, tag = "5")]
        Self_(super::SelfConfigSource),
    }
}
/// Configuration source specifier for a late-bound extension configuration. The
/// parent resource is warmed until all the initial extension configurations are
/// received, unless the flag to apply the default configuration is set.
/// Subsequent extension updates are atomic on a per-worker basis. Once an
/// extension configuration is applied to a request or a connection, it remains
/// constant for the duration of processing. If the initial delivery of the
/// extension configuration fails, due to a timeout for example, the optional
/// default configuration is applied. Without a default configuration, the
/// extension is disabled, until an extension configuration is received. The
/// behavior of a disabled extension depends on the context. For example, a
/// filter chain with a disabled extension filter rejects all incoming streams.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExtensionConfigSource {
    #[prost(message, optional, tag = "1")]
    pub config_source: ::core::option::Option<ConfigSource>,
    /// Optional default configuration to use as the initial configuration if
    /// there is a failure to receive the initial extension configuration or if
    /// `apply_default_config_without_warming` flag is set.
    #[prost(message, optional, tag = "2")]
    pub default_config: ::core::option::Option<::prost_types::Any>,
    /// Use the default config as the initial configuration without warming and
    /// waiting for the first discovery response. Requires the default configuration
    /// to be supplied.
    #[prost(bool, tag = "3")]
    pub apply_default_config_without_warming: bool,
    /// A set of permitted extension type URLs. Extension configuration updates are rejected
    /// if they do not match any type URL in the set.
    #[prost(string, repeated, tag = "4")]
    pub type_urls: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// xDS API and non-xDS services version. This is used to describe both resource and transport
/// protocol versions (in distinct configuration fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ApiVersion {
    /// When not specified, we assume v2, to ease migration to Envoy's stable API
    /// versioning. If a client does not support v2 (e.g. due to deprecation), this
    /// is an invalid value.
    Auto = 0,
    /// Use xDS v2 API.
    V2 = 1,
    /// Use xDS v3 API.
    V3 = 2,
}
impl ApiVersion {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ApiVersion::Auto => "AUTO",
            ApiVersion::V2 => "V2",
            ApiVersion::V3 => "V3",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "AUTO" => Some(Self::Auto),
            "V2" => Some(Self::V2),
            "V3" => Some(Self::V3),
            _ => None,
        }
    }
}
/// Generic UDP socket configuration.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UdpSocketConfig {
    /// The maximum size of received UDP datagrams. Using a larger size will cause Envoy to allocate
    /// more memory per socket. Received datagrams above this size will be dropped. If not set
    /// defaults to 1500 bytes.
    #[prost(message, optional, tag = "1")]
    pub max_rx_datagram_size: ::core::option::Option<u64>,
    /// Configures whether Generic Receive Offload (GRO)
    /// <<https://en.wikipedia.org/wiki/Large_receive_offload>_> is preferred when reading from the
    /// UDP socket. The default is context dependent and is documented where UdpSocketConfig is used.
    /// This option affects performance but not functionality. If GRO is not supported by the operating
    /// system, non-GRO receive will be used.
    #[prost(message, optional, tag = "2")]
    pub prefer_gro: ::core::option::Option<bool>,
}
/// \[#not-implemented-hide:\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TcpProtocolOptions {}
/// Config for keepalive probes in a QUIC connection.
/// Note that QUIC keep-alive probing packets work differently from HTTP/2
/// keep-alive PINGs in a sense that the probing packet itself doesn't timeout
/// waiting for a probing response. Quic has a shorter idle timeout than TCP, so
/// it doesn't rely on such probing to discover dead connections. If the peer
/// fails to respond, the connection will idle timeout eventually. Thus, they are
/// configured differently from :ref:`connection_keepalive
/// <envoy_v3_api_field_config.core.v3.Http2ProtocolOptions.connection_keepalive>`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuicKeepAliveSettings {
    /// The max interval for a connection to send keep-alive probing packets (with
    /// PING or PATH_RESPONSE). The value should be smaller than :ref:`connection
    /// idle_timeout
    /// <envoy_v3_api_field_config.listener.v3.QuicProtocolOptions.idle_timeout>`
    /// to prevent idle timeout while not less than 1s to avoid throttling the
    /// connection or flooding the peer with probes.
    ///
    /// If :ref:`initial_interval
    /// <envoy_v3_api_field_config.core.v3.QuicKeepAliveSettings.initial_interval>`
    /// is absent or zero, a client connection will use this value to start
    /// probing.
    ///
    /// If zero, disable keepalive probing.
    /// If absent, use the QUICHE default interval to probe.
    #[prost(message, optional, tag = "1")]
    pub max_interval: ::core::option::Option<::prost_types::Duration>,
    /// The interval to send the first few keep-alive probing packets to prevent
    /// connection from hitting the idle timeout. Subsequent probes will be sent,
    /// each one with an interval exponentially longer than previous one, till it
    /// reaches :ref:`max_interval
    /// <envoy_v3_api_field_config.core.v3.QuicKeepAliveSettings.max_interval>`.
    /// And the probes afterwards will always use :ref:`max_interval
    /// <envoy_v3_api_field_config.core.v3.QuicKeepAliveSettings.max_interval>`.
    ///
    /// The value should be smaller than :ref:`connection idle_timeout
    /// <envoy_v3_api_field_config.listener.v3.QuicProtocolOptions.idle_timeout>`
    /// to prevent idle timeout and smaller than max_interval to take effect.
    ///
    /// If absent or zero, disable keepalive probing for a server connection. For a
    /// client connection, if :ref:`max_interval
    /// <envoy_v3_api_field_config.core.v3.QuicKeepAliveSettings.max_interval>`  is
    /// also zero, do not keepalive, otherwise use max_interval or QUICHE default
    /// to probe all the time.
    #[prost(message, optional, tag = "2")]
    pub initial_interval: ::core::option::Option<::prost_types::Duration>,
}
/// QUIC protocol options which apply to both downstream and upstream
/// connections.
/// \[#next-free-field: 6\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuicProtocolOptions {
    /// Maximum number of streams that the client can negotiate per connection. 100
    /// if not specified.
    #[prost(message, optional, tag = "1")]
    pub max_concurrent_streams: ::core::option::Option<u32>,
    /// `Initial stream-level flow-control receive window
    /// <<https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-4.1>`_>
    /// size. Valid values range from 1 to 16777216 (2^24, maximum supported by
    /// QUICHE) and defaults to 65536 (2^16).
    ///
    /// NOTE: 16384 (2^14) is the minimum window size supported in Google QUIC. If
    /// configured smaller than it, we will use 16384 instead. QUICHE IETF Quic
    /// implementation supports 1 bytes window. We only support increasing the
    /// default window size now, so it's also the minimum.
    ///
    /// This field also acts as a soft limit on the number of bytes Envoy will
    /// buffer per-stream in the QUIC stream send and receive buffers. Once the
    /// buffer reaches this pointer, watermark callbacks will fire to stop the flow
    /// of data to the stream buffers.
    #[prost(message, optional, tag = "2")]
    pub initial_stream_window_size: ::core::option::Option<u32>,
    /// Similar to *initial_stream_window_size*, but for connection-level
    /// flow-control. Valid values rage from 1 to 25165824 (24MB, maximum supported
    /// by QUICHE) and defaults to 65536 (2^16). window. Currently, this has the
    /// same minimum/default as *initial_stream_window_size*.
    ///
    /// NOTE: 16384 (2^14) is the minimum window size supported in Google QUIC. We
    /// only support increasing the default window size now, so it's also the
    /// minimum.
    #[prost(message, optional, tag = "3")]
    pub initial_connection_window_size: ::core::option::Option<u32>,
    /// The number of timeouts that can occur before port migration is triggered
    /// for QUIC clients. This defaults to 1. If set to 0, port migration will not
    /// occur on path degrading. Timeout here refers to QUIC internal path
    /// degrading timeout mechanism, such as PTO. This has no effect on server
    /// sessions.
    #[prost(message, optional, tag = "4")]
    pub num_timeouts_to_trigger_port_migration: ::core::option::Option<u32>,
    /// Probes the peer at the configured interval to solicit traffic, i.e. ACK or
    /// PATH_RESPONSE, from the peer to push back connection idle timeout. If
    /// absent, use the default keepalive behavior of which a client connection
    /// sends PINGs every 15s, and a server connection doesn't do anything.
    #[prost(message, optional, tag = "5")]
    pub connection_keepalive: ::core::option::Option<QuicKeepAliveSettings>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpstreamHttpProtocolOptions {
    /// Set transport socket `SNI
    /// <<https://en.wikipedia.org/wiki/Server_Name_Indication>`_> for new upstream
    /// connections based on the downstream HTTP host/authority header or any other
    /// arbitrary header when :ref:`override_auto_sni_header
    /// <envoy_v3_api_field_config.core.v3.UpstreamHttpProtocolOptions.override_auto_sni_header>`
    /// is set, as seen by the :ref:`router filter <config_http_filters_router>`.
    #[prost(bool, tag = "1")]
    pub auto_sni: bool,
    /// Automatic validate upstream presented certificate for new upstream
    /// connections based on the downstream HTTP host/authority header or any other
    /// arbitrary header when :ref:`override_auto_sni_header
    /// <envoy_v3_api_field_config.core.v3.UpstreamHttpProtocolOptions.override_auto_sni_header>`
    /// is set, as seen by the :ref:`router filter <config_http_filters_router>`.
    /// This field is intended to be set with `auto_sni` field.
    #[prost(bool, tag = "2")]
    pub auto_san_validation: bool,
    /// An optional alternative to the host/authority header to be used for setting
    /// the SNI value. It should be a valid downstream HTTP header, as seen by the
    /// :ref:`router filter <config_http_filters_router>`.
    /// If unset, host/authority header will be used for populating the SNI. If the
    /// specified header is not found or the value is empty, host/authority header
    /// will be used instead. This field is intended to be set with `auto_sni`
    /// and/or `auto_san_validation` fields. If none of these fields are set then
    /// setting this would be a no-op.
    #[prost(string, tag = "3")]
    pub override_auto_sni_header: ::prost::alloc::string::String,
}
/// Configures the alternate protocols cache which tracks alternate protocols
/// that can be used to make an HTTP connection to an origin server. See
/// <https://tools.ietf.org/html/rfc7838> for HTTP Alternative Services and
/// <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-04> for the
/// "HTTPS" DNS resource record.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AlternateProtocolsCacheOptions {
    /// The name of the cache. Multiple named caches allow independent alternate
    /// protocols cache configurations to operate within a single Envoy process
    /// using different configurations. All alternate protocols cache options with
    /// the same name *must* be equal in all fields when referenced from different
    /// configuration components. Configuration will fail to load if this is not
    /// the case.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// The maximum number of entries that the cache will hold. If not specified
    /// defaults to 1024.
    ///
    /// .. note:
    ///
///```ignore
    ///    The implementation is approximate and enforced independently on each
    ///    worker thread, thus it is possible for the maximum entries in the cache
    ///    to go slightly above the configured value depending on timing. This is
    ///    similar to how other circuit breakers work.
///```
    #[prost(message, optional, tag = "2")]
    pub max_entries: ::core::option::Option<u32>,
    /// Allows configuring a persistent
    /// :ref:`key value store
    /// <envoy_v3_api_msg_config.common.key_value.v3.KeyValueStoreConfig>` to flush
    /// alternate protocols entries to disk.
    /// This function is currently only supported if concurrency is 1
    /// Cached entries will take precedence over pre-populated entries below.
    #[prost(message, optional, tag = "3")]
    pub key_value_store_config: ::core::option::Option<TypedExtensionConfig>,
    /// Allows pre-populating the cache with entries, as described above.
    #[prost(message, repeated, tag = "4")]
    pub prepopulated_entries: ::prost::alloc::vec::Vec<
        alternate_protocols_cache_options::AlternateProtocolsCacheEntry,
    >,
}
/// Nested message and enum types in `AlternateProtocolsCacheOptions`.
pub mod alternate_protocols_cache_options {
    /// Allows pre-populating the cache with HTTP/3 alternate protocols entries
    /// with a 7 day lifetime. This will cause Envoy to attempt HTTP/3 to those
    /// upstreams, even if the upstreams have not advertised HTTP/3 support. These
    /// entries will be overwritten by alt-svc response headers or cached values.
    /// As with regular cached entries, if the origin response would result in
    /// clearing an existing alternate protocol cache entry, pre-populated entries
    /// will also be cleared. Adding a cache entry with hostname=foo.com port=123
    /// is the equivalent of getting response headers alt-svc: h3=:"123"; ma=86400"
    /// in a response to a request to foo.com:123
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AlternateProtocolsCacheEntry {
        /// The host name for the alternate protocol entry.
        #[prost(string, tag = "1")]
        pub hostname: ::prost::alloc::string::String,
        /// The port for the alternate protocol entry.
        #[prost(uint32, tag = "2")]
        pub port: u32,
    }
}
/// \[#next-free-field: 7\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HttpProtocolOptions {
    /// The idle timeout for connections. The idle timeout is defined as the
    /// period in which there are no active requests. When the
    /// idle timeout is reached the connection will be closed. If the connection is
    /// an HTTP/2 downstream connection a drain sequence will occur prior to
    /// closing the connection, see :ref:`drain_timeout
    /// <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.drain_timeout>`.
    /// Note that request based timeouts mean that HTTP/2 PINGs will not keep the
    /// connection alive. If not specified, this defaults to 1 hour. To disable
    /// idle timeouts explicitly set this to 0.
    ///
    /// .. warning::
///```ignore
    ///    Disabling this timeout has a highly likelihood of yielding connection
    ///    leaks due to lost TCP FIN packets, etc.
///```
    ///
    /// If the :ref:`overload action <config_overload_manager_overload_actions>`
    /// "envoy.overload_actions.reduce_timeouts" is configured, this timeout is
    /// scaled for downstream connections according to the value for
    /// :ref:`HTTP_DOWNSTREAM_CONNECTION_IDLE
    /// <envoy_v3_api_enum_value_config.overload.v3.ScaleTimersOverloadActionConfig.TimerType.HTTP_DOWNSTREAM_CONNECTION_IDLE>`.
    #[prost(message, optional, tag = "1")]
    pub idle_timeout: ::core::option::Option<::prost_types::Duration>,
    /// The maximum duration of a connection. The duration is defined as a period
    /// since a connection was established. If not set, there is no max duration.
    /// When max_connection_duration is reached and if there are no active streams,
    /// the connection will be closed. If the connection is a downstream connection
    /// and there are any active streams, the drain sequence will kick-in, and the
    /// connection will be force-closed after the drain period. See
    /// :ref:`drain_timeout
    /// <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.drain_timeout>`.
    #[prost(message, optional, tag = "3")]
    pub max_connection_duration: ::core::option::Option<::prost_types::Duration>,
    /// The maximum number of headers. If unconfigured, the default
    /// maximum number of request headers allowed is 100. Requests that exceed this
    /// limit will receive a 431 response for HTTP/1.x and cause a stream reset for
    /// HTTP/2.
    #[prost(message, optional, tag = "2")]
    pub max_headers_count: ::core::option::Option<u32>,
    /// Total duration to keep alive an HTTP request/response stream. If the time
    /// limit is reached the stream will be reset independent of any other
    /// timeouts. If not specified, this value is not set.
    #[prost(message, optional, tag = "4")]
    pub max_stream_duration: ::core::option::Option<::prost_types::Duration>,
    /// Action to take when a client request with a header name containing
    /// underscore characters is received. If this setting is not specified, the
    /// value defaults to ALLOW. Note: upstream responses are not affected by this
    /// setting. Note: this only affects client headers. It does not affect headers
    /// added by Envoy filters and does not have any impact if added to cluster
    /// config.
    #[prost(
        enumeration = "http_protocol_options::HeadersWithUnderscoresAction",
        tag = "5"
    )]
    pub headers_with_underscores_action: i32,
    /// Optional maximum requests for both upstream and downstream connections.
    /// If not specified, there is no limit.
    /// Setting this parameter to 1 will effectively disable keep alive.
    /// For HTTP/2 and HTTP/3, due to concurrent stream processing, the limit is
    /// approximate.
    #[prost(message, optional, tag = "6")]
    pub max_requests_per_connection: ::core::option::Option<u32>,
}
/// Nested message and enum types in `HttpProtocolOptions`.
pub mod http_protocol_options {
    /// Action to take when Envoy receives client request with header names
    /// containing underscore characters. Underscore character is allowed in header
    /// names by the RFC-7230 and this behavior is implemented as a security
    /// measure due to systems that treat '_' and '-' as interchangeable. Envoy by
    /// default allows client request headers with underscore characters.
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum HeadersWithUnderscoresAction {
        /// Allow headers with underscores. This is the default behavior.
        Allow = 0,
        /// Reject client request. HTTP/1 requests are rejected with the 400 status.
        /// HTTP/2 requests end with the stream reset. The
        /// "httpN.requests_rejected_with_underscores_in_headers" counter is
        /// incremented for each rejected request.
        RejectRequest = 1,
        /// Drop the client header with name containing underscores. The header is
        /// dropped before the filter chain is invoked and as such filters will not
        /// see dropped headers. The "httpN.dropped_headers_with_underscores" is
        /// incremented for each dropped header.
        DropHeader = 2,
    }
    impl HeadersWithUnderscoresAction {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                HeadersWithUnderscoresAction::Allow => "ALLOW",
                HeadersWithUnderscoresAction::RejectRequest => "REJECT_REQUEST",
                HeadersWithUnderscoresAction::DropHeader => "DROP_HEADER",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "ALLOW" => Some(Self::Allow),
                "REJECT_REQUEST" => Some(Self::RejectRequest),
                "DROP_HEADER" => Some(Self::DropHeader),
                _ => None,
            }
        }
    }
}
/// \[#next-free-field: 8\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Http1ProtocolOptions {
    /// Handle HTTP requests with absolute URLs in the requests. These requests
    /// are generally sent by clients to forward/explicit proxies. This allows
    /// clients to configure envoy as their HTTP proxy. In Unix, for example, this
    /// is typically done by setting the *http_proxy* environment variable.
    #[prost(message, optional, tag = "1")]
    pub allow_absolute_url: ::core::option::Option<bool>,
    /// Handle incoming HTTP/1.0 and HTTP 0.9 requests.
    /// This is off by default, and not fully standards compliant. There is support
    /// for pre-HTTP/1.1 style connect logic, dechunking, and handling lack of
    /// client host iff *default_host_for_http_10* is configured.
    #[prost(bool, tag = "2")]
    pub accept_http_10: bool,
    /// A default host for HTTP/1.0 requests. This is highly suggested if
    /// *accept_http_10* is true as Envoy does not otherwise support HTTP/1.0
    /// without a Host header. This is a no-op if *accept_http_10* is not true.
    #[prost(string, tag = "3")]
    pub default_host_for_http_10: ::prost::alloc::string::String,
    /// Describes how the keys for response headers should be formatted. By
    /// default, all header keys are lower cased.
    #[prost(message, optional, tag = "4")]
    pub header_key_format: ::core::option::Option<
        http1_protocol_options::HeaderKeyFormat,
    >,
    /// Enables trailers for HTTP/1. By default the HTTP/1 codec drops proxied
    /// trailers.
    ///
    /// .. attention::
    ///
///```ignore
    ///    Note that this only happens when Envoy is chunk encoding which occurs
    ///    when:
    ///    - The request is HTTP/1.1.
    ///    - Is neither a HEAD only request nor a HTTP Upgrade.
    ///    - Not a response to a HEAD request.
    ///    - The content length header is not present.
///```
    #[prost(bool, tag = "5")]
    pub enable_trailers: bool,
    /// Allows Envoy to process requests/responses with both `Content-Length` and
    /// `Transfer-Encoding` headers set. By default such messages are rejected, but
    /// if option is enabled - Envoy will remove Content-Length header and process
    /// message. See `RFC7230, sec. 3.3.3
    /// <<https://tools.ietf.org/html/rfc7230#section-3.3.3>`_> for details.
    ///
    /// .. attention::
///```ignore
    ///    Enabling this option might lead to request smuggling vulnerability,
    ///    especially if traffic is proxied via multiple layers of proxies.
///```
    #[prost(bool, tag = "6")]
    pub allow_chunked_length: bool,
    /// Allows invalid HTTP messaging. When this option is false, then Envoy will
    /// terminate HTTP/1.1 connections upon receiving an invalid HTTP message.
    /// However, when this option is true, then Envoy will leave the HTTP/1.1
    /// connection open where possible. If set, this overrides any HCM
    /// :ref:`stream_error_on_invalid_http_messaging
    /// <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.stream_error_on_invalid_http_message>`.
    #[prost(message, optional, tag = "7")]
    pub override_stream_error_on_invalid_http_message: ::core::option::Option<bool>,
}
/// Nested message and enum types in `Http1ProtocolOptions`.
pub mod http1_protocol_options {
    /// \[#next-free-field: 9\]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct HeaderKeyFormat {
        #[prost(oneof = "header_key_format::HeaderFormat", tags = "1, 8")]
        pub header_format: ::core::option::Option<header_key_format::HeaderFormat>,
    }
    /// Nested message and enum types in `HeaderKeyFormat`.
    pub mod header_key_format {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ProperCaseWords {}
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum HeaderFormat {
            /// Formats the header by proper casing words: the first character and any
            /// character following a special character will be capitalized if it's an
            /// alpha character. For example, "content-type" becomes "Content-Type",
            /// and "foo$b#$are" becomes "Foo$B#$Are". Note that while this results in
            /// most headers following conventional casing, certain headers are not
            /// covered. For example, the "TE" header will be formatted as "Te".
            #[prost(message, tag = "1")]
            ProperCaseWords(ProperCaseWords),
            /// Configuration for stateful formatter extensions that allow using
            /// received headers to affect the output of encoding headers. E.g.,
            /// preserving case during proxying.
            /// \[#extension-category: envoy.http.stateful_header_formatters\]
            #[prost(message, tag = "8")]
            StatefulFormatter(super::super::TypedExtensionConfig),
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeepaliveSettings {
    /// Send HTTP/2 PING frames at this period, in order to test that the
    /// connection is still alive. If this is zero, interval PINGs will not be
    /// sent.
    #[prost(message, optional, tag = "1")]
    pub interval: ::core::option::Option<::prost_types::Duration>,
    /// How long to wait for a response to a keepalive PING. If a response is not
    /// received within this time period, the connection will be aborted.
    #[prost(message, optional, tag = "2")]
    pub timeout: ::core::option::Option<::prost_types::Duration>,
    /// A random jitter amount as a percentage of interval that will be added to
    /// each interval. A value of zero means there will be no jitter. The default
    /// value is 15%.
    #[prost(message, optional, tag = "3")]
    pub interval_jitter: ::core::option::Option<super::super::super::kind::v3::Percent>,
    /// If the connection has been idle for this duration, send a HTTP/2 ping ahead
    /// of new stream creation, to quickly detect dead connections.
    /// If this is zero, this type of PING will not be sent.
    /// If an interval ping is outstanding, a second ping will not be sent as the
    /// interval ping will determine if the connection is dead.
    ///
    /// The same feature for HTTP/3 is given by inheritance from QUICHE which uses
    /// :ref:`connection idle_timeout
    /// <envoy_v3_api_field_config.listener.v3.QuicProtocolOptions.idle_timeout>`
    /// and the current PTO of the connection to decide whether to probe before
    /// sending a new request.
    #[prost(message, optional, tag = "4")]
    pub connection_idle_interval: ::core::option::Option<::prost_types::Duration>,
}
/// \[#next-free-field: 16\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Http2ProtocolOptions {
    /// `Maximum table size
    /// <<https://httpwg.org/specs/rfc7541.html#rfc.section.4.2>`_> (in octets) that
    /// the encoder is permitted to use for the dynamic HPACK table. Valid values
    /// range from 0 to 4294967295 (2^32 - 1) and defaults to 4096. 0 effectively
    /// disables header compression.
    #[prost(message, optional, tag = "1")]
    pub hpack_table_size: ::core::option::Option<u32>,
    /// `Maximum concurrent streams
    /// <<https://httpwg.org/specs/rfc7540.html#rfc.section.5.1.2>`_> allowed for
    /// peer on one HTTP/2 connection. Valid values range from 1 to 2147483647
    /// (2^31 - 1) and defaults to 2147483647.
    ///
    /// For upstream connections, this also limits how many streams Envoy will
    /// initiate concurrently on a single connection. If the limit is reached,
    /// Envoy may queue requests or establish additional connections (as allowed
    /// per circuit breaker limits).
    ///
    /// This acts as an upper bound: Envoy will lower the max concurrent streams
    /// allowed on a given connection based on upstream settings. Config dumps will
    /// reflect the configured upper bound, not the per-connection negotiated
    /// limits.
    #[prost(message, optional, tag = "2")]
    pub max_concurrent_streams: ::core::option::Option<u32>,
    /// `Initial stream-level flow-control window
    /// <<https://httpwg.org/specs/rfc7540.html#rfc.section.6.9.2>`_> size. Valid
    /// values range from 65535 (2^16 - 1, HTTP/2 default) to 2147483647 (2^31 - 1,
    /// HTTP/2 maximum) and defaults to 268435456 (256 * 1024 * 1024).
    ///
    /// NOTE: 65535 is the initial window size from HTTP/2 spec. We only support
    /// increasing the default window size now, so it's also the minimum.
    ///
    /// This field also acts as a soft limit on the number of bytes Envoy will
    /// buffer per-stream in the HTTP/2 codec buffers. Once the buffer reaches this
    /// pointer, watermark callbacks will fire to stop the flow of data to the
    /// codec buffers.
    #[prost(message, optional, tag = "3")]
    pub initial_stream_window_size: ::core::option::Option<u32>,
    /// Similar to *initial_stream_window_size*, but for connection-level
    /// flow-control window. Currently, this has the same minimum/maximum/default
    /// as *initial_stream_window_size*.
    #[prost(message, optional, tag = "4")]
    pub initial_connection_window_size: ::core::option::Option<u32>,
    /// Allows proxying Websocket and other upgrades over H2 connect.
    #[prost(bool, tag = "5")]
    pub allow_connect: bool,
    /// \[#not-implemented-hide:\] Hiding until envoy has full metadata support.
    /// Still under implementation. DO NOT USE.
    ///
    /// Allows metadata. See [metadata
    /// docs](<https://github.com/envoyproxy/envoy/blob/main/source/docs/h2_metadata.md>)
    /// for more information.
    #[prost(bool, tag = "6")]
    pub allow_metadata: bool,
    /// Limit the number of pending outbound downstream frames of all types (frames
    /// that are waiting to be written into the socket). Exceeding this limit
    /// triggers flood mitigation and connection is terminated. The
    /// ``http2.outbound_flood`` stat tracks the number of terminated connections
    /// due to flood mitigation. The default limit is 10000.
    #[prost(message, optional, tag = "7")]
    pub max_outbound_frames: ::core::option::Option<u32>,
    /// Limit the number of pending outbound downstream frames of types PING,
    /// SETTINGS and RST_STREAM, preventing high memory utilization when receiving
    /// continuous stream of these frames. Exceeding this limit triggers flood
    /// mitigation and connection is terminated. The
    /// ``http2.outbound_control_flood`` stat tracks the number of terminated
    /// connections due to flood mitigation. The default limit is 1000.
    #[prost(message, optional, tag = "8")]
    pub max_outbound_control_frames: ::core::option::Option<u32>,
    /// Limit the number of consecutive inbound frames of types HEADERS,
    /// CONTINUATION and DATA with an empty payload and no end stream flag. Those
    /// frames have no legitimate use and are abusive, but might be a result of a
    /// broken HTTP/2 implementation. The `http2.inbound_empty_frames_flood`` stat
    /// tracks the number of connections terminated due to flood mitigation.
    /// Setting this to 0 will terminate connection upon receiving first frame with
    /// an empty payload and no end stream flag. The default limit is 1.
    #[prost(message, optional, tag = "9")]
    pub max_consecutive_inbound_frames_with_empty_payload: ::core::option::Option<u32>,
    /// Limit the number of inbound PRIORITY frames allowed per each opened stream.
    /// If the number of PRIORITY frames received over the lifetime of connection
    /// exceeds the value calculated using this formula::
    ///
///```ignore
    ///    max_inbound_priority_frames_per_stream * (1 + opened_streams)
///```
    ///
    /// the connection is terminated. For downstream connections the
    /// `opened_streams` is incremented when Envoy receives complete response
    /// headers from the upstream server. For upstream connection the
    /// `opened_streams` is incremented when Envoy send the HEADERS frame for a new
    /// stream. The
    /// ``http2.inbound_priority_frames_flood`` stat tracks
    /// the number of connections terminated due to flood mitigation. The default
    /// limit is 100.
    #[prost(message, optional, tag = "10")]
    pub max_inbound_priority_frames_per_stream: ::core::option::Option<u32>,
    /// Limit the number of inbound WINDOW_UPDATE frames allowed per DATA frame
    /// sent. If the number of WINDOW_UPDATE frames received over the lifetime of
    /// connection exceeds the value calculated using this formula::
    ///
///```ignore
    ///    5 + 2 * (opened_streams +
    ///             max_inbound_window_update_frames_per_data_frame_sent *
    ///             outbound_data_frames)
///```
    ///
    /// the connection is terminated. For downstream connections the
    /// `opened_streams` is incremented when Envoy receives complete response
    /// headers from the upstream server. For upstream connections the
    /// `opened_streams` is incremented when Envoy sends the HEADERS frame for a
    /// new stream. The
    /// ``http2.inbound_priority_frames_flood`` stat tracks the number of
    /// connections terminated due to flood mitigation. The default
    /// max_inbound_window_update_frames_per_data_frame_sent value is 10. Setting
    /// this to 1 should be enough to support HTTP/2 implementations with basic
    /// flow control, but more complex implementations that try to estimate
    /// available bandwidth require at least 2.
    #[prost(message, optional, tag = "11")]
    pub max_inbound_window_update_frames_per_data_frame_sent: ::core::option::Option<
        u32,
    >,
    /// Allows invalid HTTP messaging and headers. When this option is disabled
    /// (default), then the whole HTTP/2 connection is terminated upon receiving
    /// invalid HEADERS frame. However, when this option is enabled, only the
    /// offending stream is terminated.
    ///
    /// This is overridden by HCM :ref:`stream_error_on_invalid_http_messaging
    /// <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.stream_error_on_invalid_http_message>`
    /// iff present.
    ///
    /// This is deprecated in favor of
    /// :ref:`override_stream_error_on_invalid_http_message
    /// <envoy_v3_api_field_config.core.v3.Http2ProtocolOptions.override_stream_error_on_invalid_http_message>`
    ///
    /// See `RFC7540, sec. 8.1 <<https://tools.ietf.org/html/rfc7540#section-8.1>`_>
    /// for details.
    #[deprecated]
    #[prost(bool, tag = "12")]
    pub stream_error_on_invalid_http_messaging: bool,
    /// Allows invalid HTTP messaging and headers. When this option is disabled
    /// (default), then the whole HTTP/2 connection is terminated upon receiving
    /// invalid HEADERS frame. However, when this option is enabled, only the
    /// offending stream is terminated.
    ///
    /// This overrides any HCM :ref:`stream_error_on_invalid_http_messaging
    /// <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.stream_error_on_invalid_http_message>`
    ///
    /// See `RFC7540, sec. 8.1 <<https://tools.ietf.org/html/rfc7540#section-8.1>`_>
    /// for details.
    #[prost(message, optional, tag = "14")]
    pub override_stream_error_on_invalid_http_message: ::core::option::Option<bool>,
    /// \[#not-implemented-hide:\]
    /// Specifies SETTINGS frame parameters to be sent to the peer, with two
    /// exceptions:
    ///
    /// 1. SETTINGS_ENABLE_PUSH (0x2) is not configurable as HTTP/2 server push is
    /// not supported by Envoy.
    ///
    /// 2. SETTINGS_ENABLE_CONNECT_PROTOCOL (0x8) is only configurable through the
    /// named field 'allow_connect'.
    ///
    /// Note that custom parameters specified through this field can not also be
    /// set in the corresponding named parameters:
    ///
    /// .. code-block:: text
    ///
///```ignore
    ///    ID    Field Name
    ///    ----------------
    ///    0x1   hpack_table_size
    ///    0x3   max_concurrent_streams
    ///    0x4   initial_stream_window_size
///```
    ///
    /// Collisions will trigger config validation failure on load/update. Likewise,
    /// inconsistencies between custom parameters with the same identifier will
    /// trigger a failure.
    ///
    /// See `IANA HTTP/2 Settings
    /// <<https://www.iana.org/assignments/http2-parameters/http2-parameters.xhtml#settings>`_>
    /// for standardized identifiers.
    #[prost(message, repeated, tag = "13")]
    pub custom_settings_parameters: ::prost::alloc::vec::Vec<
        http2_protocol_options::SettingsParameter,
    >,
    /// Send HTTP/2 PING frames to verify that the connection is still healthy. If
    /// the remote peer does not respond within the configured timeout, the
    /// connection will be aborted.
    #[prost(message, optional, tag = "15")]
    pub connection_keepalive: ::core::option::Option<KeepaliveSettings>,
}
/// Nested message and enum types in `Http2ProtocolOptions`.
pub mod http2_protocol_options {
    /// Defines a parameter to be sent in the SETTINGS frame.
    /// See `RFC7540, sec. 6.5.1
    /// <<https://tools.ietf.org/html/rfc7540#section-6.5.1>`_> for details.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SettingsParameter {
        /// The 16 bit parameter identifier.
        #[prost(message, optional, tag = "1")]
        pub identifier: ::core::option::Option<u32>,
        /// The 32 bit parameter value.
        #[prost(message, optional, tag = "2")]
        pub value: ::core::option::Option<u32>,
    }
}
/// \[#not-implemented-hide:\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GrpcProtocolOptions {
    #[prost(message, optional, tag = "1")]
    pub http2_protocol_options: ::core::option::Option<Http2ProtocolOptions>,
}
/// A message which allows using HTTP/3.
/// \[#next-free-field: 6\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Http3ProtocolOptions {
    #[prost(message, optional, tag = "1")]
    pub quic_protocol_options: ::core::option::Option<QuicProtocolOptions>,
    /// Allows invalid HTTP messaging and headers. When this option is disabled
    /// (default), then the whole HTTP/3 connection is terminated upon receiving
    /// invalid HEADERS frame. However, when this option is enabled, only the
    /// offending stream is terminated.
    ///
    /// If set, this overrides any HCM :ref:`stream_error_on_invalid_http_messaging
    /// <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.stream_error_on_invalid_http_message>`.
    #[prost(message, optional, tag = "2")]
    pub override_stream_error_on_invalid_http_message: ::core::option::Option<bool>,
    /// Allows proxying Websocket and other upgrades over HTTP/3 CONNECT using
    /// the header mechanisms from the `HTTP/2 extended connect RFC
    /// <<https://datatracker.ietf.org/doc/html/rfc8441>`_>
    /// and settings `proposed for HTTP/3
    /// <<https://datatracker.ietf.org/doc/draft-ietf-httpbis-h3-websockets/>`_>
    /// Note that HTTP/3 CONNECT is not yet an RFC.
    #[prost(bool, tag = "5")]
    pub allow_extended_connect: bool,
}
/// A message to control transformations to the :scheme header
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SchemeHeaderTransformation {
    #[prost(oneof = "scheme_header_transformation::Transformation", tags = "1")]
    pub transformation: ::core::option::Option<
        scheme_header_transformation::Transformation,
    >,
}
/// Nested message and enum types in `SchemeHeaderTransformation`.
pub mod scheme_header_transformation {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Transformation {
        /// Overwrite any Scheme header with the contents of this string.
        #[prost(string, tag = "1")]
        SchemeToOverwrite(::prost::alloc::string::String),
    }
}
/// \[#not-implemented-hide:\]
/// Configuration of the event reporting service endpoint.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventServiceConfig {
    #[prost(oneof = "event_service_config::ConfigSourceSpecifier", tags = "1")]
    pub config_source_specifier: ::core::option::Option<
        event_service_config::ConfigSourceSpecifier,
    >,
}
/// Nested message and enum types in `EventServiceConfig`.
pub mod event_service_config {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ConfigSourceSpecifier {
        /// Specifies the gRPC service that hosts the event reporting service.
        #[prost(message, tag = "1")]
        GrpcService(super::GrpcService),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HealthStatusSet {
    /// An order-independent set of health status.
    #[prost(enumeration = "HealthStatus", repeated, packed = "false", tag = "1")]
    pub statuses: ::prost::alloc::vec::Vec<i32>,
}
/// \[#next-free-field: 25\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HealthCheck {
    /// The time to wait for a health check response. If the timeout is reached the
    /// health check attempt will be considered a failure.
    #[prost(message, optional, tag = "1")]
    pub timeout: ::core::option::Option<::prost_types::Duration>,
    /// The interval between health checks.
    #[prost(message, optional, tag = "2")]
    pub interval: ::core::option::Option<::prost_types::Duration>,
    /// An optional jitter amount in milliseconds. If specified, Envoy will start
    /// health checking after for a random time in ms between 0 and initial_jitter.
    /// This only applies to the first health check.
    #[prost(message, optional, tag = "20")]
    pub initial_jitter: ::core::option::Option<::prost_types::Duration>,
    /// An optional jitter amount in milliseconds. If specified, during every
    /// interval Envoy will add interval_jitter to the wait time.
    #[prost(message, optional, tag = "3")]
    pub interval_jitter: ::core::option::Option<::prost_types::Duration>,
    /// An optional jitter amount as a percentage of interval_ms. If specified,
    /// during every interval Envoy will add interval_ms *
    /// interval_jitter_percent / 100 to the wait time.
    ///
    /// If interval_jitter_ms and interval_jitter_percent are both set, both of
    /// them will be used to increase the wait time.
    #[prost(uint32, tag = "18")]
    pub interval_jitter_percent: u32,
    /// The number of unhealthy health checks required before a host is marked
    /// unhealthy. Note that for *http* health checking if a host responds with a
    /// code not in :ref:`expected_statuses
    /// <envoy_v3_api_field_config.core.v3.HealthCheck.HttpHealthCheck.expected_statuses>`
    /// or :ref:`retriable_statuses
    /// <envoy_v3_api_field_config.core.v3.HealthCheck.HttpHealthCheck.retriable_statuses>`,
    /// this threshold is ignored and the host is considered immediately unhealthy.
    #[prost(message, optional, tag = "4")]
    pub unhealthy_threshold: ::core::option::Option<u32>,
    /// The number of healthy health checks required before a host is marked
    /// healthy. Note that during startup, only a single successful health check is
    /// required to mark a host healthy.
    #[prost(message, optional, tag = "5")]
    pub healthy_threshold: ::core::option::Option<u32>,
    /// \[#not-implemented-hide:\] Non-serving port for health checking.
    #[prost(message, optional, tag = "6")]
    pub alt_port: ::core::option::Option<u32>,
    /// Reuse health check connection between health checks. Default is true.
    #[prost(message, optional, tag = "7")]
    pub reuse_connection: ::core::option::Option<bool>,
    /// The "no traffic interval" is a special health check interval that is used
    /// when a cluster has never had traffic routed to it. This lower interval
    /// allows cluster information to be kept up to date, without sending a
    /// potentially large amount of active health checking traffic for no reason.
    /// Once a cluster has been used for traffic routing, Envoy will shift back to
    /// using the standard health check interval that is defined. Note that this
    /// interval takes precedence over any other.
    ///
    /// The default value for "no traffic interval" is 60 seconds.
    #[prost(message, optional, tag = "12")]
    pub no_traffic_interval: ::core::option::Option<::prost_types::Duration>,
    /// The "no traffic healthy interval" is a special health check interval that
    /// is used for hosts that are currently passing active health checking
    /// (including new hosts) when the cluster has received no traffic.
    ///
    /// This is useful for when we want to send frequent health checks with
    /// `no_traffic_interval` but then revert to lower frequency
    /// `no_traffic_healthy_interval` once a host in the cluster is marked as
    /// healthy.
    ///
    /// Once a cluster has been used for traffic routing, Envoy will shift back to
    /// using the standard health check interval that is defined.
    ///
    /// If no_traffic_healthy_interval is not set, it will default to the
    /// no traffic interval and send that interval regardless of health state.
    #[prost(message, optional, tag = "24")]
    pub no_traffic_healthy_interval: ::core::option::Option<::prost_types::Duration>,
    /// The "unhealthy interval" is a health check interval that is used for hosts
    /// that are marked as unhealthy. As soon as the host is marked as healthy,
    /// Envoy will shift back to using the standard health check interval that is
    /// defined.
    ///
    /// The default value for "unhealthy interval" is the same as "interval".
    #[prost(message, optional, tag = "14")]
    pub unhealthy_interval: ::core::option::Option<::prost_types::Duration>,
    /// The "unhealthy edge interval" is a special health check interval that is
    /// used for the first health check right after a host is marked as unhealthy.
    /// For subsequent health checks Envoy will shift back to using either
    /// "unhealthy interval" if present or the standard health check interval that
    /// is defined.
    ///
    /// The default value for "unhealthy edge interval" is the same as "unhealthy
    /// interval".
    #[prost(message, optional, tag = "15")]
    pub unhealthy_edge_interval: ::core::option::Option<::prost_types::Duration>,
    /// The "healthy edge interval" is a special health check interval that is used
    /// for the first health check right after a host is marked as healthy. For
    /// subsequent health checks Envoy will shift back to using the standard health
    /// check interval that is defined.
    ///
    /// The default value for "healthy edge interval" is the same as the default
    /// interval.
    #[prost(message, optional, tag = "16")]
    pub healthy_edge_interval: ::core::option::Option<::prost_types::Duration>,
    /// Specifies the path to the :ref:`health check event log
    /// <arch_overview_health_check_logging>`. If empty, no event log will be
    /// written.
    #[prost(string, tag = "17")]
    pub event_log_path: ::prost::alloc::string::String,
    /// \[#not-implemented-hide:\]
    /// The gRPC service for the health check event service.
    /// If empty, health check events won't be sent to a remote endpoint.
    #[prost(message, optional, tag = "22")]
    pub event_service: ::core::option::Option<EventServiceConfig>,
    /// If set to true, health check failure events will always be logged. If set
    /// to false, only the initial health check failure event will be logged. The
    /// default value is false.
    #[prost(bool, tag = "19")]
    pub always_log_health_check_failures: bool,
    /// This allows overriding the cluster TLS settings, just for health check
    /// connections.
    #[prost(message, optional, tag = "21")]
    pub tls_options: ::core::option::Option<health_check::TlsOptions>,
    /// Optional key/value pairs that will be used to match a transport socket from
    /// those specified in the cluster's :ref:`tranport socket matches
    /// <envoy_v3_api_field_config.cluster.v3.Cluster.transport_socket_matches>`.
    /// For example, the following match criteria
    ///
    /// .. code-block:: yaml
    ///
    ///   transport_socket_match_criteria:
///```ignore
    ///     useMTLS: true
///```
    ///
    /// Will match the following :ref:`cluster socket match
    /// <envoy_v3_api_msg_config.cluster.v3.Cluster.TransportSocketMatch>`
    ///
    /// .. code-block:: yaml
    ///
    ///   transport_socket_matches:
    ///   - name: "useMTLS"
///```ignore
    ///     match:
    ///       useMTLS: true
    ///     transport_socket:
    ///       name: envoy.transport_sockets.tls
    ///       config: { ... } # tls socket configuration
///```
    ///
    /// If this field is set, then for health checks it will supersede an entry of
    /// *envoy.transport_socket* in the :ref:`LbEndpoint.Metadata
    /// <envoy_v3_api_field_config.endpoint.v3.LbEndpoint.metadata>`. This allows
    /// using different transport socket capabilities for health checking versus
    /// proxying to the endpoint.
    ///
    /// If the key/values pairs specified do not match any
    /// :ref:`transport socket matches
    /// <envoy_v3_api_field_config.cluster.v3.Cluster.transport_socket_matches>`,
    /// the cluster's :ref:`transport socket
    /// <envoy_v3_api_field_config.cluster.v3.Cluster.transport_socket>` will be
    /// used for health check socket configuration.
    #[prost(message, optional, tag = "23")]
    pub transport_socket_match_criteria: ::core::option::Option<::prost_types::Struct>,
    #[prost(oneof = "health_check::HealthChecker", tags = "8, 9, 11, 13")]
    pub health_checker: ::core::option::Option<health_check::HealthChecker>,
}
/// Nested message and enum types in `HealthCheck`.
pub mod health_check {
    /// Describes the encoding of the payload bytes in the payload.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Payload {
        #[prost(oneof = "payload::Payload", tags = "1, 2")]
        pub payload: ::core::option::Option<payload::Payload>,
    }
    /// Nested message and enum types in `Payload`.
    pub mod payload {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Payload {
            /// Hex encoded payload. E.g., "000000FF".
            #[prost(string, tag = "1")]
            Text(::prost::alloc::string::String),
            /// \[#not-implemented-hide:\] Binary payload.
            #[prost(bytes, tag = "2")]
            Binary(::prost::alloc::vec::Vec<u8>),
        }
    }
    /// \[#next-free-field: 13\]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct HttpHealthCheck {
        /// The value of the host header in the HTTP health check request. If
        /// left empty (default value), the name of the cluster this health check is
        /// associated with will be used. The host header can be customized for a
        /// specific endpoint by setting the :ref:`hostname
        /// <envoy_v3_api_field_config.endpoint.v3.Endpoint.HealthCheckConfig.hostname>`
        /// field.
        #[prost(string, tag = "1")]
        pub host: ::prost::alloc::string::String,
        /// Specifies the HTTP path that will be requested during health checking.
        /// For example
        /// */healthcheck*.
        #[prost(string, tag = "2")]
        pub path: ::prost::alloc::string::String,
        /// \[#not-implemented-hide:\] HTTP specific payload.
        #[prost(message, optional, tag = "3")]
        pub send: ::core::option::Option<Payload>,
        /// \[#not-implemented-hide:\] HTTP specific response.
        #[prost(message, optional, tag = "4")]
        pub receive: ::core::option::Option<Payload>,
        /// Specifies a list of HTTP headers that should be added to each request
        /// that is sent to the health checked cluster. For more information,
        /// including details on header value syntax, see the documentation on
        /// :ref:`custom request headers
        /// <config_http_conn_man_headers_custom_request_headers>`.
        #[prost(message, repeated, tag = "6")]
        pub request_headers_to_add: ::prost::alloc::vec::Vec<super::HeaderValueOption>,
        /// Specifies a list of HTTP headers that should be removed from each request
        /// that is sent to the health checked cluster.
        #[prost(string, repeated, tag = "8")]
        pub request_headers_to_remove: ::prost::alloc::vec::Vec<
            ::prost::alloc::string::String,
        >,
        /// Specifies a list of HTTP response statuses considered healthy. If
        /// provided, replaces default 200-only policy - 200 must be included
        /// explicitly as needed. Ranges follow half-open semantics of
        /// :ref:`Int64Range <envoy_v3_api_msg_type.v3.Int64Range>`. The start and
        /// end of each range are required. Only statuses in the range [100, 600) are
        /// allowed.
        #[prost(message, repeated, tag = "9")]
        pub expected_statuses: ::prost::alloc::vec::Vec<
            super::super::super::super::kind::v3::Int64Range,
        >,
        /// Specifies a list of HTTP response statuses considered retriable. If
        /// provided, responses in this range will count towards the configured
        /// :ref:`unhealthy_threshold
        /// <envoy_v3_api_field_config.core.v3.HealthCheck.unhealthy_threshold>`, but
        /// will not result in the host being considered immediately unhealthy.
        /// Ranges follow half-open semantics of :ref:`Int64Range
        /// <envoy_v3_api_msg_type.v3.Int64Range>`. The start and end of each range
        /// are required. Only statuses in the range [100, 600) are allowed. The
        /// :ref:`expected_statuses
        /// <envoy_v3_api_field_config.core.v3.HealthCheck.HttpHealthCheck.expected_statuses>`
        /// field takes precedence for any range overlaps with this field i.e. if
        /// status code 200 is both retriable and expected, a 200 response will be
        /// considered a successful health check. By default all responses not in
        /// :ref:`expected_statuses
        /// <envoy_v3_api_field_config.core.v3.HealthCheck.HttpHealthCheck.expected_statuses>`
        /// will result in the host being considered immediately unhealthy i.e. if
        /// status code 200 is expected and there are no configured retriable
        /// statuses, any non-200 response will result in the host being marked
        /// unhealthy.
        #[prost(message, repeated, tag = "12")]
        pub retriable_statuses: ::prost::alloc::vec::Vec<
            super::super::super::super::kind::v3::Int64Range,
        >,
        /// Use specified application protocol for health checks.
        #[prost(
            enumeration = "super::super::super::super::kind::v3::CodecClientType",
            tag = "10"
        )]
        pub codec_client_type: i32,
        /// An optional service name parameter which is used to validate the identity
        /// of the health checked cluster using a :ref:`StringMatcher
        /// <envoy_v3_api_msg_type.matcher.v3.StringMatcher>`. See the
        /// :ref:`architecture overview <arch_overview_health_checking_identity>` for
        /// more information.
        #[prost(message, optional, tag = "11")]
        pub service_name_matcher: ::core::option::Option<
            super::super::super::super::kind::matcher::v3::StringMatcher,
        >,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TcpHealthCheck {
        /// Empty payloads imply a connect-only health check.
        #[prost(message, optional, tag = "1")]
        pub send: ::core::option::Option<Payload>,
        /// When checking the response, “fuzzy” matching is performed such that each
        /// binary block must be found, and in the order specified, but not
        /// necessarily contiguous.
        #[prost(message, repeated, tag = "2")]
        pub receive: ::prost::alloc::vec::Vec<Payload>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RedisHealthCheck {
        /// If set, optionally perform ``EXISTS <key>`` instead of ``PING``. A return
        /// value from Redis of 0 (does not exist) is considered a passing
        /// healthcheck. A return value other than 0 is considered a failure. This
        /// allows the user to mark a Redis instance for maintenance by setting the
        /// specified key to any value and waiting for traffic to drain.
        #[prost(string, tag = "1")]
        pub key: ::prost::alloc::string::String,
    }
    /// `grpc.health.v1.Health
    /// <<https://github.com/grpc/grpc/blob/master/src/proto/grpc/health/v1/health.proto>`_-based>
    /// healthcheck. See `gRPC doc
    /// <<https://github.com/grpc/grpc/blob/master/doc/health-checking.md>`_> for
    /// details.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GrpcHealthCheck {
        /// An optional service name parameter which will be sent to gRPC service in
        /// `grpc.health.v1.HealthCheckRequest
        /// <<https://github.com/grpc/grpc/blob/master/src/proto/grpc/health/v1/health.proto#L20>`_.>
        /// message. See `gRPC health-checking overview
        /// <<https://github.com/grpc/grpc/blob/master/doc/health-checking.md>`_> for
        /// more information.
        #[prost(string, tag = "1")]
        pub service_name: ::prost::alloc::string::String,
        /// The value of the :authority header in the gRPC health check request. If
        /// left empty (default value), the name of the cluster this health check is
        /// associated with will be used. The authority header can be customized for
        /// a specific endpoint by setting the :ref:`hostname
        /// <envoy_v3_api_field_config.endpoint.v3.Endpoint.HealthCheckConfig.hostname>`
        /// field.
        #[prost(string, tag = "2")]
        pub authority: ::prost::alloc::string::String,
        /// Specifies a list of key-value pairs that should be added to the metadata
        /// of each GRPC call that is sent to the health checked cluster. For more
        /// information, including details on header value syntax, see the
        /// documentation on :ref:`custom request headers
        /// <config_http_conn_man_headers_custom_request_headers>`.
        #[prost(message, repeated, tag = "3")]
        pub initial_metadata: ::prost::alloc::vec::Vec<super::HeaderValueOption>,
    }
    /// Custom health check.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct CustomHealthCheck {
        /// The registered name of the custom health checker.
        #[prost(string, tag = "1")]
        pub name: ::prost::alloc::string::String,
        /// A custom health checker specific configuration which depends on the
        /// custom health checker being instantiated. See
        /// :api:`envoy/config/health_checker` for reference.
        /// \[#extension-category: envoy.health_checkers\]
        #[prost(oneof = "custom_health_check::ConfigType", tags = "3")]
        pub config_type: ::core::option::Option<custom_health_check::ConfigType>,
    }
    /// Nested message and enum types in `CustomHealthCheck`.
    pub mod custom_health_check {
        /// A custom health checker specific configuration which depends on the
        /// custom health checker being instantiated. See
        /// :api:`envoy/config/health_checker` for reference.
        /// \[#extension-category: envoy.health_checkers\]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum ConfigType {
            #[prost(message, tag = "3")]
            TypedConfig(::prost_types::Any),
        }
    }
    /// Health checks occur over the transport socket specified for the cluster.
    /// This implies that if a cluster is using a TLS-enabled transport socket, the
    /// health check will also occur over TLS.
    ///
    /// This allows overriding the cluster TLS settings, just for health check
    /// connections.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TlsOptions {
        /// Specifies the ALPN protocols for health check connections. This is useful
        /// if the corresponding upstream is using ALPN-based :ref:`FilterChainMatch
        /// <envoy_v3_api_msg_config.listener.v3.FilterChainMatch>` along with
        /// different protocols for health checks versus data connections. If empty,
        /// no ALPN protocols will be set on health check connections.
        #[prost(string, repeated, tag = "1")]
        pub alpn_protocols: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum HealthChecker {
        /// HTTP health check.
        #[prost(message, tag = "8")]
        HttpHealthCheck(HttpHealthCheck),
        /// TCP health check.
        #[prost(message, tag = "9")]
        TcpHealthCheck(TcpHealthCheck),
        /// gRPC health check.
        #[prost(message, tag = "11")]
        GrpcHealthCheck(GrpcHealthCheck),
        /// Custom health check.
        #[prost(message, tag = "13")]
        CustomHealthCheck(CustomHealthCheck),
    }
}
/// Endpoint health status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum HealthStatus {
    /// The health status is not known. This is interpreted by Envoy as *HEALTHY*.
    Unknown = 0,
    /// Healthy.
    Healthy = 1,
    /// Unhealthy.
    Unhealthy = 2,
    /// Connection draining in progress. E.g.,
    /// `<<https://aws.amazon.com/blogs/aws/elb-connection-draining-remove-instances-from-service-with-care/>`_>
    /// or
    /// `<<https://cloud.google.com/compute/docs/load-balancing/enabling-connection-draining>`_.>
    /// This is interpreted by Envoy as *UNHEALTHY*.
    Draining = 3,
    /// Health check timed out. This is part of HDS and is interpreted by Envoy as
    /// *UNHEALTHY*.
    Timeout = 4,
    /// Degraded.
    Degraded = 5,
}
impl HealthStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            HealthStatus::Unknown => "UNKNOWN",
            HealthStatus::Healthy => "HEALTHY",
            HealthStatus::Unhealthy => "UNHEALTHY",
            HealthStatus::Draining => "DRAINING",
            HealthStatus::Timeout => "TIMEOUT",
            HealthStatus::Degraded => "DEGRADED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UNKNOWN" => Some(Self::Unknown),
            "HEALTHY" => Some(Self::Healthy),
            "UNHEALTHY" => Some(Self::Unhealthy),
            "DRAINING" => Some(Self::Draining),
            "TIMEOUT" => Some(Self::Timeout),
            "DEGRADED" => Some(Self::Degraded),
            _ => None,
        }
    }
}
