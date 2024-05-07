#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApiListener {
    #[prost(message, optional, tag = "1")]
    pub api_listener: ::core::option::Option<::prost_types::Any>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Filter {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(oneof = "filter::ConfigType", tags = "4, 5")]
    pub config_type: ::core::option::Option<filter::ConfigType>,
}
/// Nested message and enum types in `Filter`.
pub mod filter {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ConfigType {
        #[prost(message, tag = "4")]
        TypedConfig(::prost_types::Any),
        #[prost(message, tag = "5")]
        ConfigDiscovery(super::super::super::core::v3::ExtensionConfigSource),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FilterChainMatch {
    #[prost(message, optional, tag = "8")]
    pub destination_port: ::core::option::Option<u32>,
    #[prost(message, repeated, tag = "3")]
    pub prefix_ranges: ::prost::alloc::vec::Vec<super::super::core::v3::CidrRange>,
    #[prost(string, tag = "4")]
    pub address_suffix: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "5")]
    pub suffix_len: ::core::option::Option<u32>,
    #[prost(message, repeated, tag = "13")]
    pub direct_source_prefix_ranges: ::prost::alloc::vec::Vec<super::super::core::v3::CidrRange>,
    #[prost(enumeration = "filter_chain_match::ConnectionSourceType", tag = "12")]
    pub source_type: i32,
    #[prost(message, repeated, tag = "6")]
    pub source_prefix_ranges: ::prost::alloc::vec::Vec<super::super::core::v3::CidrRange>,
    #[prost(uint32, repeated, packed = "false", tag = "7")]
    pub source_ports: ::prost::alloc::vec::Vec<u32>,
    #[prost(string, repeated, tag = "11")]
    pub server_names: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "9")]
    pub transport_protocol: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "10")]
    pub application_protocols: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Nested message and enum types in `FilterChainMatch`.
pub mod filter_chain_match {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ConnectionSourceType {
        Any = 0,
        SameIpOrLoopback = 1,
        External = 2,
    }
    impl ConnectionSourceType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ConnectionSourceType::Any => "ANY",
                ConnectionSourceType::SameIpOrLoopback => "SAME_IP_OR_LOOPBACK",
                ConnectionSourceType::External => "EXTERNAL",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "ANY" => Some(Self::Any),
                "SAME_IP_OR_LOOPBACK" => Some(Self::SameIpOrLoopback),
                "EXTERNAL" => Some(Self::External),
                _ => None,
            }
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FilterChain {
    #[prost(message, optional, tag = "1")]
    pub filter_chain_match: ::core::option::Option<FilterChainMatch>,
    #[prost(message, repeated, tag = "3")]
    pub filters: ::prost::alloc::vec::Vec<Filter>,
    #[deprecated]
    #[prost(message, optional, tag = "4")]
    pub use_proxy_proto: ::core::option::Option<bool>,
    #[prost(message, optional, tag = "5")]
    pub metadata: ::core::option::Option<super::super::core::v3::Metadata>,
    #[prost(message, optional, tag = "6")]
    pub transport_socket: ::core::option::Option<super::super::core::v3::TransportSocket>,
    #[prost(message, optional, tag = "9")]
    pub transport_socket_connect_timeout: ::core::option::Option<::prost_types::Duration>,
    #[prost(string, tag = "7")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "8")]
    pub on_demand_configuration: ::core::option::Option<filter_chain::OnDemandConfiguration>,
}
/// Nested message and enum types in `FilterChain`.
pub mod filter_chain {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct OnDemandConfiguration {
        #[prost(message, optional, tag = "1")]
        pub rebuild_timeout: ::core::option::Option<::prost_types::Duration>,
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListenerFilterChainMatchPredicate {
    #[prost(
        oneof = "listener_filter_chain_match_predicate::Rule",
        tags = "1, 2, 3, 4, 5"
    )]
    pub rule: ::core::option::Option<listener_filter_chain_match_predicate::Rule>,
}
/// Nested message and enum types in `ListenerFilterChainMatchPredicate`.
pub mod listener_filter_chain_match_predicate {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MatchSet {
        #[prost(message, repeated, tag = "1")]
        pub rules: ::prost::alloc::vec::Vec<super::ListenerFilterChainMatchPredicate>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Rule {
        #[prost(message, tag = "1")]
        OrMatch(MatchSet),
        #[prost(message, tag = "2")]
        AndMatch(MatchSet),
        #[prost(message, tag = "3")]
        NotMatch(::prost::alloc::boxed::Box<super::ListenerFilterChainMatchPredicate>),
        #[prost(bool, tag = "4")]
        AnyMatch(bool),
        #[prost(message, tag = "5")]
        DestinationPortRange(super::super::super::super::kind::v3::Int32Range),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListenerFilter {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub filter_disabled: ::core::option::Option<ListenerFilterChainMatchPredicate>,
    #[prost(oneof = "listener_filter::ConfigType", tags = "3, 5")]
    pub config_type: ::core::option::Option<listener_filter::ConfigType>,
}
/// Nested message and enum types in `ListenerFilter`.
pub mod listener_filter {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ConfigType {
        #[prost(message, tag = "3")]
        TypedConfig(::prost_types::Any),
        #[prost(message, tag = "5")]
        ConfigDiscovery(super::super::super::core::v3::ExtensionConfigSource),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuicProtocolOptions {
    #[prost(message, optional, tag = "1")]
    pub quic_protocol_options: ::core::option::Option<super::super::core::v3::QuicProtocolOptions>,
    #[prost(message, optional, tag = "2")]
    pub idle_timeout: ::core::option::Option<::prost_types::Duration>,
    #[prost(message, optional, tag = "3")]
    pub crypto_handshake_timeout: ::core::option::Option<::prost_types::Duration>,
    #[prost(message, optional, tag = "4")]
    pub enabled: ::core::option::Option<super::super::core::v3::RuntimeFeatureFlag>,
    #[prost(message, optional, tag = "5")]
    pub packets_to_read_to_connection_count_ratio: ::core::option::Option<u32>,
    #[prost(message, optional, tag = "6")]
    pub crypto_stream_config: ::core::option::Option<super::super::core::v3::TypedExtensionConfig>,
    #[prost(message, optional, tag = "7")]
    pub proof_source_config: ::core::option::Option<super::super::core::v3::TypedExtensionConfig>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UdpListenerConfig {
    #[prost(message, optional, tag = "5")]
    pub downstream_socket_config: ::core::option::Option<super::super::core::v3::UdpSocketConfig>,
    #[prost(message, optional, tag = "7")]
    pub quic_options: ::core::option::Option<QuicProtocolOptions>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActiveRawUdpListenerConfig {}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListenerCollection {
    #[prost(message, repeated, tag = "1")]
    pub entries:
        ::prost::alloc::vec::Vec<super::super::super::super::xds::core::v3::CollectionEntry>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Listener {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub address: ::core::option::Option<super::super::core::v3::Address>,
    #[prost(string, tag = "28")]
    pub stat_prefix: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub filter_chains: ::prost::alloc::vec::Vec<FilterChain>,
    #[prost(message, optional, tag = "4")]
    pub use_original_dst: ::core::option::Option<bool>,
    #[prost(message, optional, tag = "25")]
    pub default_filter_chain: ::core::option::Option<FilterChain>,
    #[prost(message, optional, tag = "5")]
    pub per_connection_buffer_limit_bytes: ::core::option::Option<u32>,
    #[prost(message, optional, tag = "6")]
    pub metadata: ::core::option::Option<super::super::core::v3::Metadata>,
    #[deprecated]
    #[prost(message, optional, tag = "7")]
    pub deprecated_v1: ::core::option::Option<listener::DeprecatedV1>,
    #[prost(enumeration = "listener::DrainType", tag = "8")]
    pub drain_type: i32,
    #[prost(message, repeated, tag = "9")]
    pub listener_filters: ::prost::alloc::vec::Vec<ListenerFilter>,
    #[prost(message, optional, tag = "15")]
    pub listener_filters_timeout: ::core::option::Option<::prost_types::Duration>,
    #[prost(bool, tag = "17")]
    pub continue_on_listener_filters_timeout: bool,
    #[prost(message, optional, tag = "10")]
    pub transparent: ::core::option::Option<bool>,
    #[prost(message, optional, tag = "11")]
    pub freebind: ::core::option::Option<bool>,
    #[prost(message, repeated, tag = "13")]
    pub socket_options: ::prost::alloc::vec::Vec<super::super::core::v3::SocketOption>,
    #[prost(message, optional, tag = "12")]
    pub tcp_fast_open_queue_length: ::core::option::Option<u32>,
    #[prost(enumeration = "super::super::core::v3::TrafficDirection", tag = "16")]
    pub traffic_direction: i32,
    #[prost(message, optional, tag = "18")]
    pub udp_listener_config: ::core::option::Option<UdpListenerConfig>,
    #[prost(message, optional, tag = "19")]
    pub api_listener: ::core::option::Option<ApiListener>,
    #[prost(message, optional, tag = "20")]
    pub connection_balance_config: ::core::option::Option<listener::ConnectionBalanceConfig>,
    #[deprecated]
    #[prost(bool, tag = "21")]
    pub reuse_port: bool,
    #[prost(message, optional, tag = "29")]
    pub enable_reuse_port: ::core::option::Option<bool>,
    #[prost(message, repeated, tag = "22")]
    pub access_log: ::prost::alloc::vec::Vec<super::super::accesslog::v3::AccessLog>,
    #[prost(message, optional, tag = "24")]
    pub tcp_backlog_size: ::core::option::Option<u32>,
    #[prost(message, optional, tag = "26")]
    pub bind_to_port: ::core::option::Option<bool>,
    #[prost(bool, tag = "30")]
    pub enable_mptcp: bool,
    #[prost(bool, tag = "31")]
    pub ignore_global_conn_limit: bool,
    #[prost(oneof = "listener::ListenerSpecifier", tags = "27")]
    pub listener_specifier: ::core::option::Option<listener::ListenerSpecifier>,
}
/// Nested message and enum types in `Listener`.
pub mod listener {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DeprecatedV1 {
        #[prost(message, optional, tag = "1")]
        pub bind_to_port: ::core::option::Option<bool>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ConnectionBalanceConfig {
        #[prost(oneof = "connection_balance_config::BalanceType", tags = "1")]
        pub balance_type: ::core::option::Option<connection_balance_config::BalanceType>,
    }
    /// Nested message and enum types in `ConnectionBalanceConfig`.
    pub mod connection_balance_config {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ExactBalance {}
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum BalanceType {
            #[prost(message, tag = "1")]
            ExactBalance(ExactBalance),
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct InternalListenerConfig {}
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum DrainType {
        Default = 0,
        ModifyOnly = 1,
    }
    impl DrainType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                DrainType::Default => "DEFAULT",
                DrainType::ModifyOnly => "MODIFY_ONLY",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "DEFAULT" => Some(Self::Default),
                "MODIFY_ONLY" => Some(Self::ModifyOnly),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ListenerSpecifier {
        #[prost(message, tag = "27")]
        InternalListener(InternalListenerConfig),
    }
}
