/// Upstream host identifier.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Endpoint {
    /// The upstream host address.
    ///
    /// .. attention::
    ///
///```ignore
    ///    The form of host address depends on the given cluster type. For STATIC or
    ///    EDS, it is expected to be a direct IP address (or something resolvable by
    ///    the specified :ref:`resolver
    ///    <envoy_v3_api_field_config.core.v3.SocketAddress.resolver_name>` in the
    ///    Address). For LOGICAL or STRICT DNS, it is expected to be hostname, and
    ///    will be resolved via DNS.
///```
    #[prost(message, optional, tag = "1")]
    pub address: ::core::option::Option<super::super::core::v3::Address>,
    /// The optional health check configuration is used as configuration for the
    /// health checker to contact the health checked host.
    ///
    /// .. attention::
    ///
///```ignore
    ///    This takes into effect only for upstream clusters with
    ///    :ref:`active health checking <arch_overview_health_checking>` enabled.
///```
    #[prost(message, optional, tag = "2")]
    pub health_check_config: ::core::option::Option<endpoint::HealthCheckConfig>,
    /// The hostname associated with this endpoint. This hostname is not used for
    /// routing or address resolution. If provided, it will be associated with the
    /// endpoint, and can be used for features that require a hostname, like
    /// :ref:`auto_host_rewrite
    /// <envoy_v3_api_field_config.route.v3.RouteAction.auto_host_rewrite>`.
    #[prost(string, tag = "3")]
    pub hostname: ::prost::alloc::string::String,
}
/// Nested message and enum types in `Endpoint`.
pub mod endpoint {
    /// The optional health check configuration.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct HealthCheckConfig {
        /// Optional alternative health check port value.
        ///
        /// By default the health check address port of an upstream host is the same
        /// as the host's serving address port. This provides an alternative health
        /// check port. Setting this with a non-zero value allows an upstream host
        /// to have different health check address port.
        #[prost(uint32, tag = "1")]
        pub port_value: u32,
        /// By default, the host header for L7 health checks is controlled by cluster
        /// level configuration (see: :ref:`host
        /// <envoy_v3_api_field_config.core.v3.HealthCheck.HttpHealthCheck.host>` and
        /// :ref:`authority
        /// <envoy_v3_api_field_config.core.v3.HealthCheck.GrpcHealthCheck.authority>`).
        /// Setting this to a non-empty value allows overriding the cluster level
        /// configuration for a specific endpoint.
        #[prost(string, tag = "2")]
        pub hostname: ::prost::alloc::string::String,
    }
}
/// An Endpoint that Envoy can route traffic to.
/// \[#next-free-field: 6\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LbEndpoint {
    /// Optional health status when known and supplied by EDS server.
    #[prost(enumeration = "super::super::core::v3::HealthStatus", tag = "2")]
    pub health_status: i32,
    /// The endpoint metadata specifies values that may be used by the load
    /// balancer to select endpoints in a cluster for a given request. The filter
    /// name should be specified as *envoy.lb*. An example boolean key-value pair
    /// is *canary*, providing the optional canary status of the upstream host.
    /// This may be matched against in a route's
    /// :ref:`RouteAction <envoy_v3_api_msg_config.route.v3.RouteAction>`
    /// metadata_match field to subset the endpoints considered in cluster load
    /// balancing.
    #[prost(message, optional, tag = "3")]
    pub metadata: ::core::option::Option<super::super::core::v3::Metadata>,
    /// The optional load balancing weight of the upstream host; at least 1.
    /// Envoy uses the load balancing weight in some of the built in load
    /// balancers. The load balancing weight for an endpoint is divided by the sum
    /// of the weights of all endpoints in the endpoint's locality to produce a
    /// percentage of traffic for the endpoint. This percentage is then further
    /// weighted by the endpoint's locality's load balancing weight from
    /// LocalityLbEndpoints. If unspecified, each host is presumed to have equal
    /// weight in a locality. The sum of the weights of all endpoints in the
    /// endpoint's locality must not exceed uint32_t maximal value (4294967295).
    #[prost(message, optional, tag = "4")]
    pub load_balancing_weight: ::core::option::Option<u32>,
    /// Upstream host identifier or a named reference.
    #[prost(oneof = "lb_endpoint::HostIdentifier", tags = "1, 5")]
    pub host_identifier: ::core::option::Option<lb_endpoint::HostIdentifier>,
}
/// Nested message and enum types in `LbEndpoint`.
pub mod lb_endpoint {
    /// Upstream host identifier or a named reference.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum HostIdentifier {
        #[prost(message, tag = "1")]
        Endpoint(super::Endpoint),
        /// \[#not-implemented-hide:\]
        #[prost(string, tag = "5")]
        EndpointName(::prost::alloc::string::String),
    }
}
/// \[#not-implemented-hide:\]
/// A configuration for a LEDS collection.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LedsClusterLocalityConfig {
    /// Configuration for the source of LEDS updates for a Locality.
    #[prost(message, optional, tag = "1")]
    pub leds_config: ::core::option::Option<super::super::core::v3::ConfigSource>,
    /// The xDS transport protocol glob collection resource name.
    /// The service is only supported in delta xDS (incremental) mode.
    #[prost(string, tag = "2")]
    pub leds_collection_name: ::prost::alloc::string::String,
}
/// A group of endpoints belonging to a Locality.
/// One can have multiple LocalityLbEndpoints for a locality, but this is
/// generally only done if the different groups need to have different load
/// balancing weights or different priorities.
/// \[#next-free-field: 9\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LocalityLbEndpoints {
    /// Identifies location of where the upstream hosts run.
    #[prost(message, optional, tag = "1")]
    pub locality: ::core::option::Option<super::super::core::v3::Locality>,
    /// The group of endpoints belonging to the locality specified.
    /// [#comment:TODO(adisuissa): Once LEDS is implemented this field needs to be
    /// deprecated and replaced by *load_balancer_endpoints*.]
    #[prost(message, repeated, tag = "2")]
    pub lb_endpoints: ::prost::alloc::vec::Vec<LbEndpoint>,
    /// Optional: Per priority/region/zone/sub_zone weight; at least 1. The load
    /// balancing weight for a locality is divided by the sum of the weights of all
    /// localities  at the same priority level to produce the effective percentage
    /// of traffic for the locality. The sum of the weights of all localities at
    /// the same priority level must not exceed uint32_t maximal value
    /// (4294967295).
    ///
    /// Locality weights are only considered when :ref:`locality weighted load
    /// balancing <arch_overview_load_balancing_locality_weighted_lb>` is
    /// configured. These weights are ignored otherwise. If no weights are
    /// specified when locality weighted load balancing is enabled, the locality is
    /// assigned no load.
    #[prost(message, optional, tag = "3")]
    pub load_balancing_weight: ::core::option::Option<u32>,
    /// Optional: the priority for this LocalityLbEndpoints. If unspecified this
    /// will default to the highest priority (0).
    ///
    /// Under usual circumstances, Envoy will only select endpoints for the highest
    /// priority (0). In the event all endpoints for a particular priority are
    /// unavailable/unhealthy, Envoy will fail over to selecting endpoints for the
    /// next highest priority group.
    ///
    /// Priorities should range from 0 (highest) to N (lowest) without skipping.
    #[prost(uint32, tag = "5")]
    pub priority: u32,
    /// Optional: Per locality proximity value which indicates how close this
    /// locality is from the source locality. This value only provides ordering
    /// information (lower the value, closer it is to the source locality).
    /// This will be consumed by load balancing schemes that need proximity order
    /// to determine where to route the requests.
    /// \[#not-implemented-hide:\]
    #[prost(message, optional, tag = "6")]
    pub proximity: ::core::option::Option<u32>,
    /// \[#not-implemented-hide:\]
    #[prost(oneof = "locality_lb_endpoints::LbConfig", tags = "7, 8")]
    pub lb_config: ::core::option::Option<locality_lb_endpoints::LbConfig>,
}
/// Nested message and enum types in `LocalityLbEndpoints`.
pub mod locality_lb_endpoints {
    /// \[#not-implemented-hide:\]
    /// A list of endpoints of a specific locality.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LbEndpointList {
        #[prost(message, repeated, tag = "1")]
        pub lb_endpoints: ::prost::alloc::vec::Vec<super::LbEndpoint>,
    }
    /// \[#not-implemented-hide:\]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum LbConfig {
        /// The group of endpoints belonging to the locality.
        /// [#comment:TODO(adisuissa): Once LEDS is implemented the *lb_endpoints*
        /// field needs to be deprecated.]
        #[prost(message, tag = "7")]
        LoadBalancerEndpoints(LbEndpointList),
        /// LEDS Configuration for the current locality.
        #[prost(message, tag = "8")]
        LedsClusterLocalityConfig(super::LedsClusterLocalityConfig),
    }
}
