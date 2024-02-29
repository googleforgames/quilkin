/// Describes a type of API listener, which is used in non-proxy clients. The
/// type of API exposed to the non-proxy application depends on the type of API
/// listener.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApiListener {
    /// The type in this field determines the type of API listener. At present, the
    /// following types are supported:
    /// envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
    /// (HTTP)
    /// envoy.extensions.filters.network.http_connection_manager.v3.EnvoyMobileHttpConnectionManager
    /// (HTTP)
    /// [#next-major-version: In the v3 API, replace this Any field with a oneof
    /// containing the specific config message for each type of API listener. We
    /// could not do this in v2 because it would have caused circular dependencies
    /// for go protos: lds.proto depends on this file, and
    /// http_connection_manager.proto depends on rds.proto, which is in the same
    /// directory as lds.proto, so lds.proto cannot depend on this file.]
    #[prost(message, optional, tag = "1")]
    pub api_listener: ::core::option::Option<::prost_types::Any>,
}
/// \[#next-free-field: 6\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Filter {
    /// The name of the filter to instantiate. The name must match a
    /// :ref:`supported filter <config_network_filters>`.
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
        /// Filter specific configuration which depends on the filter being
        /// instantiated. See the supported filters for further documentation.
        /// \[#extension-category: envoy.filters.network\]
        #[prost(message, tag = "4")]
        TypedConfig(::prost_types::Any),
        /// Configuration source specifier for an extension configuration discovery
        /// service. In case of a failure and without the default configuration, the
        /// listener closes the connections.
        /// \[#not-implemented-hide:\]
        #[prost(message, tag = "5")]
        ConfigDiscovery(super::super::super::core::v3::ExtensionConfigSource),
    }
}
/// Specifies the match criteria for selecting a specific filter chain for a
/// listener.
///
/// In order for a filter chain to be selected, *ALL* of its criteria must be
/// fulfilled by the incoming connection, properties of which are set by the
/// networking stack and/or listener filters.
///
/// The following order applies:
///
/// 1. Destination port.
/// 2. Destination IP address.
/// 3. Server name (e.g. SNI for TLS protocol),
/// 4. Transport protocol.
/// 5. Application protocols (e.g. ALPN for TLS protocol).
/// 6. Directly connected source IP address (this will only be different from the
/// source IP address
///```ignore
///     when using a listener filter that overrides the source address, such as
///     the :ref:`Proxy Protocol listener filter
///     <config_listener_filters_proxy_protocol>`).
///```
/// 7. Source type (e.g. any, local or external network).
/// 8. Source IP address.
/// 9. Source port.
///
/// For criteria that allow ranges or wildcards, the most specific value in any
/// of the configured filter chains that matches the incoming connection is going
/// to be used (e.g. for SNI ``www.example.com`` the most specific match would be
/// ``www.example.com``, then ``*.example.com``, then ``*.com``, then any filter
/// chain without ``server_names`` requirements).
///
/// A different way to reason about the filter chain matches:
/// Suppose there exists N filter chains. Prune the filter chain set using the
/// above 8 steps. In each step, filter chains which most specifically matches
/// the attributes continue to the next step. The listener guarantees at most 1
/// filter chain is left after all of the steps.
///
/// Example:
///
/// For destination port, filter chains specifying the destination port of
/// incoming traffic are the most specific match. If none of the filter chains
/// specifies the exact destination port, the filter chains which do not specify
/// ports are the most specific match. Filter chains specifying the wrong port
/// can never be the most specific match.
///
/// [#comment: Implemented rules are kept in the preference order, with
/// deprecated fields listed at the end, because that's how we want to list them
/// in the docs.
///
/// [#comment:TODO(PiotrSikora): Add support for configurable precedence of the
/// rules]
/// \[#next-free-field: 14\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FilterChainMatch {
    /// Optional destination port to consider when use_original_dst is set on the
    /// listener in determining a filter chain match.
    #[prost(message, optional, tag = "8")]
    pub destination_port: ::core::option::Option<u32>,
    /// If non-empty, an IP address and prefix length to match addresses when the
    /// listener is bound to 0.0.0.0/:: or when use_original_dst is specified.
    #[prost(message, repeated, tag = "3")]
    pub prefix_ranges: ::prost::alloc::vec::Vec<super::super::core::v3::CidrRange>,
    /// If non-empty, an IP address and suffix length to match addresses when the
    /// listener is bound to 0.0.0.0/:: or when use_original_dst is specified.
    /// \[#not-implemented-hide:\]
    #[prost(string, tag = "4")]
    pub address_suffix: ::prost::alloc::string::String,
    /// \[#not-implemented-hide:\]
    #[prost(message, optional, tag = "5")]
    pub suffix_len: ::core::option::Option<u32>,
    /// The criteria is satisfied if the directly connected source IP address of
    /// the downstream connection is contained in at least one of the specified
    /// subnets. If the parameter is not specified or the list is empty, the
    /// directly connected source IP address is ignored.
    #[prost(message, repeated, tag = "13")]
    pub direct_source_prefix_ranges: ::prost::alloc::vec::Vec<super::super::core::v3::CidrRange>,
    /// Specifies the connection source IP match type. Can be any, local or
    /// external network.
    #[prost(enumeration = "filter_chain_match::ConnectionSourceType", tag = "12")]
    pub source_type: i32,
    /// The criteria is satisfied if the source IP address of the downstream
    /// connection is contained in at least one of the specified subnets. If the
    /// parameter is not specified or the list is empty, the source IP address is
    /// ignored.
    #[prost(message, repeated, tag = "6")]
    pub source_prefix_ranges: ::prost::alloc::vec::Vec<super::super::core::v3::CidrRange>,
    /// The criteria is satisfied if the source port of the downstream connection
    /// is contained in at least one of the specified ports. If the parameter is
    /// not specified, the source port is ignored.
    #[prost(uint32, repeated, packed = "false", tag = "7")]
    pub source_ports: ::prost::alloc::vec::Vec<u32>,
    /// If non-empty, a list of server names (e.g. SNI for TLS protocol) to
    /// consider when determining a filter chain match. Those values will be
    /// compared against the server names of a new connection, when detected by one
    /// of the listener filters.
    ///
    /// The server name will be matched against all wildcard domains, i.e.
    /// ``www.example.com`` will be first matched against ``www.example.com``, then
    /// ``*.example.com``, then ``*.com``.
    ///
    /// Note that partial wildcards are not supported, and values like
    /// ``*w.example.com`` are invalid.
    ///
    /// .. attention::
    ///
    ///```ignore
    ///    See the :ref:`FAQ entry <faq_how_to_setup_sni>` on how to configure SNI
    ///    for more information.
    ///```
    #[prost(string, repeated, tag = "11")]
    pub server_names: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// If non-empty, a transport protocol to consider when determining a filter
    /// chain match. This value will be compared against the transport protocol of
    /// a new connection, when it's detected by one of the listener filters.
    ///
    /// Suggested values include:
    ///
    /// * ``raw_buffer`` - default, used when no transport protocol is detected,
    /// * ``tls`` - set by :ref:`envoy.filters.listener.tls_inspector
    /// <config_listener_filters_tls_inspector>`
    ///```ignore
    ///    when TLS protocol is detected.
    ///```
    #[prost(string, tag = "9")]
    pub transport_protocol: ::prost::alloc::string::String,
    /// If non-empty, a list of application protocols (e.g. ALPN for TLS protocol)
    /// to consider when determining a filter chain match. Those values will be
    /// compared against the application protocols of a new connection, when
    /// detected by one of the listener filters.
    ///
    /// Suggested values include:
    ///
    /// * ``http/1.1`` - set by :ref:`envoy.filters.listener.tls_inspector
    ///```ignore
    ///    <config_listener_filters_tls_inspector>`,
    ///```
    /// * ``h2`` - set by :ref:`envoy.filters.listener.tls_inspector
    /// <config_listener_filters_tls_inspector>`
    ///
    /// .. attention::
    ///
    ///```ignore
    ///    Currently, only :ref:`TLS Inspector
    ///    <config_listener_filters_tls_inspector>` provides application protocol
    ///    detection based on the requested `ALPN
    ///    <<https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation>`_>
    ///    values.
    ///```
    ///
    ///```ignore
    ///    However, the use of ALPN is pretty much limited to the HTTP/2 traffic on
    ///    the Internet, and matching on values other than ``h2`` is going to lead
    ///    to a lot of false negatives, unless all connecting clients are known to
    ///    use ALPN.
    ///```
    #[prost(string, repeated, tag = "10")]
    pub application_protocols: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Nested message and enum types in `FilterChainMatch`.
pub mod filter_chain_match {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ConnectionSourceType {
        /// Any connection source matches.
        Any = 0,
        /// Match a connection originating from the same host.
        SameIpOrLoopback = 1,
        /// Match a connection originating from a different host.
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
/// A filter chain wraps a set of match criteria, an option TLS context, a set of
/// filters, and various other parameters.
/// \[#next-free-field: 10\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FilterChain {
    /// The criteria to use when matching a connection to this filter chain.
    #[prost(message, optional, tag = "1")]
    pub filter_chain_match: ::core::option::Option<FilterChainMatch>,
    /// A list of individual network filters that make up the filter chain for
    /// connections established with the listener. Order matters as the filters are
    /// processed sequentially as connection events happen. Note: If the filter
    /// list is empty, the connection will close by default.
    #[prost(message, repeated, tag = "3")]
    pub filters: ::prost::alloc::vec::Vec<Filter>,
    /// Whether the listener should expect a PROXY protocol V1 header on new
    /// connections. If this option is enabled, the listener will assume that that
    /// remote address of the connection is the one specified in the header. Some
    /// load balancers including the AWS ELB support this option. If the option is
    /// absent or set to false, Envoy will use the physical peer address of the
    /// connection as the remote address.
    ///
    /// This field is deprecated. Add a
    /// :ref:`PROXY protocol listener filter
    /// <config_listener_filters_proxy_protocol>` explicitly instead.
    #[deprecated]
    #[prost(message, optional, tag = "4")]
    pub use_proxy_proto: ::core::option::Option<bool>,
    /// \[#not-implemented-hide:\] filter chain metadata.
    #[prost(message, optional, tag = "5")]
    pub metadata: ::core::option::Option<super::super::core::v3::Metadata>,
    /// Optional custom transport socket implementation to use for downstream
    /// connections. To setup TLS, set a transport socket with name
    /// `envoy.transport_sockets.tls` and :ref:`DownstreamTlsContext
    /// <envoy_v3_api_msg_extensions.transport_sockets.tls.v3.DownstreamTlsContext>`
    /// in the `typed_config`. If no transport socket configuration is specified,
    /// new connections will be set up with plaintext.
    /// \[#extension-category: envoy.transport_sockets.downstream\]
    #[prost(message, optional, tag = "6")]
    pub transport_socket: ::core::option::Option<super::super::core::v3::TransportSocket>,
    /// If present and nonzero, the amount of time to allow incoming connections to
    /// complete any transport socket negotiations. If this expires before the
    /// transport reports connection establishment, the connection is summarily
    /// closed.
    #[prost(message, optional, tag = "9")]
    pub transport_socket_connect_timeout: ::core::option::Option<::prost_types::Duration>,
    /// \[#not-implemented-hide:\] The unique name (or empty) by which this filter
    /// chain is known. If no name is provided, Envoy will allocate an internal
    /// UUID for the filter chain. If the filter chain is to be dynamically updated
    /// or removed via FCDS a unique name must be provided.
    #[prost(string, tag = "7")]
    pub name: ::prost::alloc::string::String,
    /// \[#not-implemented-hide:\] The configuration to specify whether the filter
    /// chain will be built on-demand. If this field is not empty, the filter chain
    /// will be built on-demand. Otherwise, the filter chain will be built normally
    /// and block listener warming.
    #[prost(message, optional, tag = "8")]
    pub on_demand_configuration: ::core::option::Option<filter_chain::OnDemandConfiguration>,
}
/// Nested message and enum types in `FilterChain`.
pub mod filter_chain {
    /// The configuration for on-demand filter chain. If this field is not empty in
    /// FilterChain message, a filter chain will be built on-demand. On-demand
    /// filter chains help speedup the warming up of listeners since the building
    /// and initialization of an on-demand filter chain will be postponed to the
    /// arrival of new connection requests that require this filter chain. Filter
    /// chains that are not often used can be set as on-demand.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct OnDemandConfiguration {
        /// The timeout to wait for filter chain placeholders to complete rebuilding.
        /// 1. If this field is set to 0, timeout is disabled.
        /// 2. If not specified, a default timeout of 15s is used.
        /// Rebuilding will wait until dependencies are ready, have failed, or this
        /// timeout is reached. Upon failure or timeout, all connections related to
        /// this filter chain will be closed. Rebuilding will start again on the next
        /// new connection.
        #[prost(message, optional, tag = "1")]
        pub rebuild_timeout: ::core::option::Option<::prost_types::Duration>,
    }
}
/// Listener filter chain match configuration. This is a recursive structure
/// which allows complex nested match configurations to be built using various
/// logical operators.
///
/// Examples:
///
/// * Matches if the destination port is 3306.
///
/// .. code-block:: yaml
///
///   destination_port_range:
///```ignore
///    start: 3306
///    end: 3307
///```
///
/// * Matches if the destination port is 3306 or 15000.
///
/// .. code-block:: yaml
///
///   or_match:
///```ignore
///     rules:
///       - destination_port_range:
///           start: 3306
///           end: 3307
///       - destination_port_range:
///           start: 15000
///           end: 15001
///```
///
/// \[#next-free-field: 6\]
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
    /// A set of match configurations used for logical operations.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MatchSet {
        /// The list of rules that make up the set.
        #[prost(message, repeated, tag = "1")]
        pub rules: ::prost::alloc::vec::Vec<super::ListenerFilterChainMatchPredicate>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Rule {
        /// A set that describes a logical OR. If any member of the set matches, the
        /// match configuration matches.
        #[prost(message, tag = "1")]
        OrMatch(MatchSet),
        /// A set that describes a logical AND. If all members of the set match, the
        /// match configuration matches.
        #[prost(message, tag = "2")]
        AndMatch(MatchSet),
        /// A negation match. The match configuration will match if the negated match
        /// condition matches.
        #[prost(message, tag = "3")]
        NotMatch(::prost::alloc::boxed::Box<super::ListenerFilterChainMatchPredicate>),
        /// The match configuration will always match.
        #[prost(bool, tag = "4")]
        AnyMatch(bool),
        /// Match destination port. Particularly, the match evaluation must use the
        /// recovered local port if the owning listener filter is after :ref:`an
        /// original_dst listener filter <config_listener_filters_original_dst>`.
        #[prost(message, tag = "5")]
        DestinationPortRange(super::super::super::super::kind::v3::Int32Range),
    }
}
/// \[#next-free-field: 6\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListenerFilter {
    /// The name of the filter to instantiate. The name must match a
    /// :ref:`supported filter <config_listener_filters>`.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Optional match predicate used to disable the filter. The filter is enabled
    /// when this field is empty. See :ref:`ListenerFilterChainMatchPredicate
    /// <envoy_v3_api_msg_config.listener.v3.ListenerFilterChainMatchPredicate>`
    /// for further examples.
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
        /// Filter specific configuration which depends on the filter being
        /// instantiated. See the supported filters for further documentation.
        /// \[#extension-category: envoy.filters.listener,envoy.filters.udp_listener\]
        #[prost(message, tag = "3")]
        TypedConfig(::prost_types::Any),
        /// Configuration source specifier for an extension configuration discovery
        /// service. In case of a failure and without the default configuration, the
        /// listener closes the connections.
        /// \[#not-implemented-hide:\]
        #[prost(message, tag = "5")]
        ConfigDiscovery(super::super::super::core::v3::ExtensionConfigSource),
    }
}
/// Configuration specific to the UDP QUIC listener.
/// \[#next-free-field: 8\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct QuicProtocolOptions {
    #[prost(message, optional, tag = "1")]
    pub quic_protocol_options: ::core::option::Option<super::super::core::v3::QuicProtocolOptions>,
    /// Maximum number of milliseconds that connection will be alive when there is
    /// no network activity.
    ///
    /// If it is less than 1ms, Envoy will use 1ms. 300000ms if not specified.
    #[prost(message, optional, tag = "2")]
    pub idle_timeout: ::core::option::Option<::prost_types::Duration>,
    /// Connection timeout in milliseconds before the crypto handshake is finished.
    ///
    /// If it is less than 5000ms, Envoy will use 5000ms. 20000ms if not specified.
    #[prost(message, optional, tag = "3")]
    pub crypto_handshake_timeout: ::core::option::Option<::prost_types::Duration>,
    /// Runtime flag that controls whether the listener is enabled or not. If not
    /// specified, defaults to enabled.
    #[prost(message, optional, tag = "4")]
    pub enabled: ::core::option::Option<super::super::core::v3::RuntimeFeatureFlag>,
    /// A multiplier to number of connections which is used to determine how many
    /// packets to read per event loop. A reasonable number should allow the
    /// listener to process enough payload but not starve TCP and other UDP sockets
    /// and also prevent long event loop duration. The default value is 32. This
    /// means if there are N QUIC connections, the total number of packets to read
    /// in each read event will be 32 * N. The actual number of packets to read in
    /// total by the UDP listener is also bound by 6000, regardless of this field
    /// or how many connections there are.
    #[prost(message, optional, tag = "5")]
    pub packets_to_read_to_connection_count_ratio: ::core::option::Option<u32>,
    /// Configure which implementation of `quic::QuicCryptoClientStreamBase` to be
    /// used for this listener. If not specified the :ref:`QUICHE default one
    /// configured by
    /// <envoy_v3_api_msg_extensions.quic.crypto_stream.v3.CryptoServerStreamConfig>`
    /// will be used.
    /// \[#extension-category: envoy.quic.server.crypto_stream\]
    #[prost(message, optional, tag = "6")]
    pub crypto_stream_config: ::core::option::Option<super::super::core::v3::TypedExtensionConfig>,
    /// Configure which implementation of `quic::ProofSource` to be used for this
    /// listener. If not specified the :ref:`default one configured by
    /// <envoy_v3_api_msg_extensions.quic.proof_source.v3.ProofSourceConfig>` will
    /// be used.
    /// \[#extension-category: envoy.quic.proof_source\]
    #[prost(message, optional, tag = "7")]
    pub proof_source_config: ::core::option::Option<super::super::core::v3::TypedExtensionConfig>,
}
/// \[#next-free-field: 8\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UdpListenerConfig {
    /// UDP socket configuration for the listener. The default for
    /// :ref:`prefer_gro
    /// <envoy_v3_api_field_config.core.v3.UdpSocketConfig.prefer_gro>` is false
    /// for listener sockets. If receiving a large amount of datagrams from a small
    /// number of sources, it may be worthwhile to enable this option after
    /// performance testing.
    #[prost(message, optional, tag = "5")]
    pub downstream_socket_config: ::core::option::Option<super::super::core::v3::UdpSocketConfig>,
    /// Configuration for QUIC protocol. If empty, QUIC will not be enabled on this
    /// listener. Set to the default object to enable QUIC without modifying any
    /// additional options.
    #[prost(message, optional, tag = "7")]
    pub quic_options: ::core::option::Option<QuicProtocolOptions>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActiveRawUdpListenerConfig {}
/// Listener list collections. Entries are *Listener* resources or references.
/// \[#not-implemented-hide:\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListenerCollection {
    #[prost(message, repeated, tag = "1")]
    pub entries:
        ::prost::alloc::vec::Vec<super::super::super::super::xds::core::v3::CollectionEntry>,
}
/// \[#next-free-field: 32\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Listener {
    /// The unique name by which this listener is known. If no name is provided,
    /// Envoy will allocate an internal UUID for the listener. If the listener is
    /// to be dynamically updated or removed via :ref:`LDS <config_listeners_lds>`
    /// a unique name must be provided.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// The address that the listener should listen on. In general, the address
    /// must be unique, though that is governed by the bind rules of the OS. E.g.,
    /// multiple listeners can listen on port 0 on Linux as the actual port will be
    /// allocated by the OS.
    #[prost(message, optional, tag = "2")]
    pub address: ::core::option::Option<super::super::core::v3::Address>,
    /// Optional prefix to use on listener stats. If empty, the stats will be
    /// rooted at `listener.<address as string>.`. If non-empty, stats will be
    /// rooted at `listener.<stat_prefix>.`.
    #[prost(string, tag = "28")]
    pub stat_prefix: ::prost::alloc::string::String,
    /// A list of filter chains to consider for this listener. The
    /// :ref:`FilterChain <envoy_v3_api_msg_config.listener.v3.FilterChain>` with
    /// the most specific :ref:`FilterChainMatch
    /// <envoy_v3_api_msg_config.listener.v3.FilterChainMatch>` criteria is used on
    /// a connection.
    ///
    /// Example using SNI for filter chain selection can be found in the
    /// :ref:`FAQ entry <faq_how_to_setup_sni>`.
    #[prost(message, repeated, tag = "3")]
    pub filter_chains: ::prost::alloc::vec::Vec<FilterChain>,
    /// If a connection is redirected using *iptables*, the port on which the proxy
    /// receives it might be different from the original destination address. When
    /// this flag is set to true, the listener hands off redirected connections to
    /// the listener associated with the original destination address. If there is
    /// no listener associated with the original destination address, the
    /// connection is handled by the listener that receives it. Defaults to false.
    #[prost(message, optional, tag = "4")]
    pub use_original_dst: ::core::option::Option<bool>,
    /// The default filter chain if none of the filter chain matches. If no default
    /// filter chain is supplied, the connection will be closed. The filter chain
    /// match is ignored in this field.
    #[prost(message, optional, tag = "25")]
    pub default_filter_chain: ::core::option::Option<FilterChain>,
    /// Soft limit on size of the listener’s new connection read and write buffers.
    /// If unspecified, an implementation defined default is applied (1MiB).
    #[prost(message, optional, tag = "5")]
    pub per_connection_buffer_limit_bytes: ::core::option::Option<u32>,
    /// Listener metadata.
    #[prost(message, optional, tag = "6")]
    pub metadata: ::core::option::Option<super::super::core::v3::Metadata>,
    /// \[#not-implemented-hide:\]
    #[deprecated]
    #[prost(message, optional, tag = "7")]
    pub deprecated_v1: ::core::option::Option<listener::DeprecatedV1>,
    /// The type of draining to perform at a listener-wide level.
    #[prost(enumeration = "listener::DrainType", tag = "8")]
    pub drain_type: i32,
    /// Listener filters have the opportunity to manipulate and augment the
    /// connection metadata that is used in connection filter chain matching, for
    /// example. These filters are run before any in :ref:`filter_chains
    /// <envoy_v3_api_field_config.listener.v3.Listener.filter_chains>`. Order
    /// matters as the filters are processed sequentially right after a socket has
    /// been accepted by the listener, and before a connection is created. UDP
    /// Listener filters can be specified when the protocol in the listener socket
    /// address in :ref:`protocol
    /// <envoy_v3_api_field_config.core.v3.SocketAddress.protocol>` is :ref:`UDP
    /// <envoy_v3_api_enum_value_config.core.v3.SocketAddress.Protocol.UDP>`.
    #[prost(message, repeated, tag = "9")]
    pub listener_filters: ::prost::alloc::vec::Vec<ListenerFilter>,
    /// The timeout to wait for all listener filters to complete operation. If the
    /// timeout is reached, the accepted socket is closed without a connection
    /// being created unless `continue_on_listener_filters_timeout` is set to true.
    /// Specify 0 to disable the timeout. If not specified, a default timeout of
    /// 15s is used.
    #[prost(message, optional, tag = "15")]
    pub listener_filters_timeout: ::core::option::Option<::prost_types::Duration>,
    /// Whether a connection should be created when listener filters timeout.
    /// Default is false.
    ///
    /// .. attention::
    ///
    ///```ignore
    ///    Some listener filters, such as :ref:`Proxy Protocol filter
    ///    <config_listener_filters_proxy_protocol>`, should not be used with this
    ///    option. It will cause unexpected behavior when a connection is created.
    ///```
    #[prost(bool, tag = "17")]
    pub continue_on_listener_filters_timeout: bool,
    /// Whether the listener should be set as a transparent socket.
    /// When this flag is set to true, connections can be redirected to the
    /// listener using an *iptables* *TPROXY* target, in which case the original
    /// source and destination addresses and ports are preserved on accepted
    /// connections. This flag should be used in combination with :ref:`an
    /// original_dst <config_listener_filters_original_dst>` :ref:`listener filter
    /// <envoy_v3_api_field_config.listener.v3.Listener.listener_filters>` to mark
    /// the connections' local addresses as "restored." This can be used to hand
    /// off each redirected connection to another listener associated with the
    /// connection's destination address. Direct connections to the socket without
    /// using *TPROXY* cannot be distinguished from connections redirected using
    /// *TPROXY* and are therefore treated as if they were redirected. When this
    /// flag is set to false, the listener's socket is explicitly reset as
    /// non-transparent. Setting this flag requires Envoy to run with the
    /// *CAP_NET_ADMIN* capability. When this flag is not set (default), the socket
    /// is not modified, i.e. the transparent option is neither set nor reset.
    #[prost(message, optional, tag = "10")]
    pub transparent: ::core::option::Option<bool>,
    /// Whether the listener should set the *IP_FREEBIND* socket option. When this
    /// flag is set to true, listeners can be bound to an IP address that is not
    /// configured on the system running Envoy. When this flag is set to false, the
    /// option *IP_FREEBIND* is disabled on the socket. When this flag is not set
    /// (default), the socket is not modified, i.e. the option is neither enabled
    /// nor disabled.
    #[prost(message, optional, tag = "11")]
    pub freebind: ::core::option::Option<bool>,
    /// Additional socket options that may not be present in Envoy source code or
    /// precompiled binaries.
    #[prost(message, repeated, tag = "13")]
    pub socket_options: ::prost::alloc::vec::Vec<super::super::core::v3::SocketOption>,
    /// Whether the listener should accept TCP Fast Open (TFO) connections.
    /// When this flag is set to a value greater than 0, the option TCP_FASTOPEN is
    /// enabled on the socket, with a queue length of the specified size (see
    /// `details in RFC7413 <<https://tools.ietf.org/html/rfc7413#section-5.1>`_>).
    /// When this flag is set to 0, the option TCP_FASTOPEN is disabled on the
    /// socket. When this flag is not set (default), the socket is not modified,
    /// i.e. the option is neither enabled nor disabled.
    ///
    /// On Linux, the net.ipv4.tcp_fastopen kernel parameter must include flag 0x2
    /// to enable TCP_FASTOPEN. See `ip-sysctl.txt
    /// <<https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt>`_.>
    ///
    /// On macOS, only values of 0, 1, and unset are valid; other values may result
    /// in an error. To set the queue length on macOS, set the
    /// net.inet.tcp.fastopen_backlog kernel parameter.
    #[prost(message, optional, tag = "12")]
    pub tcp_fast_open_queue_length: ::core::option::Option<u32>,
    /// Specifies the intended direction of the traffic relative to the local
    /// Envoy. This property is required on Windows for listeners using the
    /// original destination filter, see :ref:`Original Destination
    /// <config_listener_filters_original_dst>`.
    #[prost(enumeration = "super::super::core::v3::TrafficDirection", tag = "16")]
    pub traffic_direction: i32,
    /// If the protocol in the listener socket address in :ref:`protocol
    /// <envoy_v3_api_field_config.core.v3.SocketAddress.protocol>` is :ref:`UDP
    /// <envoy_v3_api_enum_value_config.core.v3.SocketAddress.Protocol.UDP>`, this
    /// field specifies UDP listener specific configuration.
    #[prost(message, optional, tag = "18")]
    pub udp_listener_config: ::core::option::Option<UdpListenerConfig>,
    /// Used to represent an API listener, which is used in non-proxy clients. The
    /// type of API exposed to the non-proxy application depends on the type of API
    /// listener. When this field is set, no other field except for
    /// :ref:`name<envoy_v3_api_field_config.listener.v3.Listener.name>` should be
    /// set.
    ///
    /// .. note::
    ///
    ///   Currently only one ApiListener can be installed; and it can only be done
    ///   via bootstrap config, not LDS.
    ///
    /// [#next-major-version: In the v3 API, instead of this messy approach where
    /// the socket listener fields are directly in the top-level Listener message
    /// and the API listener types are in the ApiListener message, the socket
    /// listener messages should be in their own message, and the top-level
    /// Listener should essentially be a oneof that selects between the socket
    /// listener and the various types of API listener. That way, a given Listener
    /// message can structurally only contain the fields of the relevant type.]
    #[prost(message, optional, tag = "19")]
    pub api_listener: ::core::option::Option<ApiListener>,
    /// The listener's connection balancer configuration, currently only applicable
    /// to TCP listeners. If no configuration is specified, Envoy will not attempt
    /// to balance active connections between worker threads.
    ///
    /// In the scenario that the listener X redirects all the connections to the
    /// listeners Y1 and Y2 by setting :ref:`use_original_dst
    /// <envoy_v3_api_field_config.listener.v3.Listener.use_original_dst>` in X and
    /// :ref:`bind_to_port
    /// <envoy_v3_api_field_config.listener.v3.Listener.bind_to_port>` to false in
    /// Y1 and Y2, it is recommended to disable the balance config in listener X to
    /// avoid the cost of balancing, and enable the balance config in Y1 and Y2 to
    /// balance the connections among the workers.
    #[prost(message, optional, tag = "20")]
    pub connection_balance_config: ::core::option::Option<listener::ConnectionBalanceConfig>,
    /// Deprecated. Use `enable_reuse_port` instead.
    #[deprecated]
    #[prost(bool, tag = "21")]
    pub reuse_port: bool,
    /// When this flag is set to true, listeners set the *SO_REUSEPORT* socket
    /// option and create one socket for each worker thread. This makes inbound
    /// connections distribute among worker threads roughly evenly in cases where
    /// there are a high number of connections. When this flag is set to false, all
    /// worker threads share one socket. This field defaults to true.
    ///
    /// .. attention::
    ///
    ///```ignore
    ///    Although this field defaults to true, it has different behavior on
    ///    different platforms. See the following text for more information.
    ///```
    ///
    /// * On Linux, reuse_port is respected for both TCP and UDP listeners. It also
    /// works correctly
    ///```ignore
    ///    with hot restart.
    ///```
    /// * On macOS, reuse_port for TCP does not do what it does on Linux. Instead
    /// of load balancing,
    ///```ignore
    ///    the last socket wins and receives all connections/packets. For TCP,
    ///    reuse_port is force disabled and the user is warned. For UDP, it is
    ///    enabled, but only one worker will receive packets. For QUIC/H3, SW
    ///    routing will send packets to other workers. For "raw" UDP, only a single
    ///    worker will currently receive packets.
    ///```
    /// * On Windows, reuse_port for TCP has undefined behavior. It is force
    /// disabled and the user
    ///```ignore
    ///    is warned similar to macOS. It is left enabled for UDP with undefined
    ///    behavior currently.
    ///```
    #[prost(message, optional, tag = "29")]
    pub enable_reuse_port: ::core::option::Option<bool>,
    /// Configuration for :ref:`access logs <arch_overview_access_logs>`
    /// emitted by this listener.
    #[prost(message, repeated, tag = "22")]
    pub access_log: ::prost::alloc::vec::Vec<super::super::accesslog::v3::AccessLog>,
    /// The maximum length a tcp listener's pending connections queue can grow to.
    /// If no value is provided net.core.somaxconn will be used on Linux and 128
    /// otherwise.
    #[prost(message, optional, tag = "24")]
    pub tcp_backlog_size: ::core::option::Option<u32>,
    /// Whether the listener should bind to the port. A listener that doesn't
    /// bind can only receive connections redirected from other listeners that set
    /// :ref:`use_original_dst
    /// <envoy_v3_api_field_config.listener.v3.Listener.use_original_dst>` to true.
    /// Default is true.
    #[prost(message, optional, tag = "26")]
    pub bind_to_port: ::core::option::Option<bool>,
    /// Enable MPTCP (multi-path TCP) on this listener. Clients will be allowed to
    /// establish MPTCP connections. Non-MPTCP clients will fall back to regular
    /// TCP.
    #[prost(bool, tag = "30")]
    pub enable_mptcp: bool,
    /// Whether the listener should limit connections based upon the value of
    /// :ref:`global_downstream_max_connections
    /// <config_overload_manager_limiting_connections>`.
    #[prost(bool, tag = "31")]
    pub ignore_global_conn_limit: bool,
    /// The exclusive listener type and the corresponding config.
    /// TODO(lambdai): <https://github.com/envoyproxy/envoy/issues/15372>
    /// Will create and add TcpListenerConfig. Will add UdpListenerConfig and
    /// ApiListener.
    /// \[#not-implemented-hide:\]
    #[prost(oneof = "listener::ListenerSpecifier", tags = "27")]
    pub listener_specifier: ::core::option::Option<listener::ListenerSpecifier>,
}
/// Nested message and enum types in `Listener`.
pub mod listener {
    /// \[#not-implemented-hide:\]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DeprecatedV1 {
        /// Whether the listener should bind to the port. A listener that doesn't
        /// bind can only receive connections redirected from other listeners that
        /// set use_original_dst parameter to true. Default is true.
        ///
        /// This is deprecated. Use :ref:`Listener.bind_to_port
        /// <envoy_v3_api_field_config.listener.v3.Listener.bind_to_port>`
        #[prost(message, optional, tag = "1")]
        pub bind_to_port: ::core::option::Option<bool>,
    }
    /// Configuration for listener connection balancing.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ConnectionBalanceConfig {
        #[prost(oneof = "connection_balance_config::BalanceType", tags = "1")]
        pub balance_type: ::core::option::Option<connection_balance_config::BalanceType>,
    }
    /// Nested message and enum types in `ConnectionBalanceConfig`.
    pub mod connection_balance_config {
        /// A connection balancer implementation that does exact balancing. This
        /// means that a lock is held during balancing so that connection counts are
        /// nearly exactly balanced between worker threads. This is "nearly" exact in
        /// the sense that a connection might close in parallel thus making the
        /// counts incorrect, but this should be rectified on the next accept. This
        /// balancer sacrifices accept throughput for accuracy and should be used
        /// when there are a small number of connections that rarely cycle (e.g.,
        /// service mesh gRPC egress).
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct ExactBalance {}
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum BalanceType {
            /// If specified, the listener will use the exact connection balancer.
            #[prost(message, tag = "1")]
            ExactBalance(ExactBalance),
        }
    }
    /// Configuration for envoy internal listener. All the future internal listener
    /// features should be added here.
    /// \[#not-implemented-hide:\]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct InternalListenerConfig {}
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum DrainType {
        /// Drain in response to calling /healthcheck/fail admin endpoint (along with
        /// the health check filter), listener removal/modification, and hot restart.
        Default = 0,
        /// Drain in response to listener removal/modification and hot restart. This
        /// setting does not include /healthcheck/fail. This setting may be desirable
        /// if Envoy is hosting both ingress and egress listeners.
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
    /// The exclusive listener type and the corresponding config.
    /// TODO(lambdai): <https://github.com/envoyproxy/envoy/issues/15372>
    /// Will create and add TcpListenerConfig. Will add UdpListenerConfig and
    /// ApiListener.
    /// \[#not-implemented-hide:\]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ListenerSpecifier {
        /// Used to represent an internal listener which does not listen on OSI L4
        /// address but can be used by the :ref:`envoy cluster
        /// <envoy_v3_api_msg_config.cluster.v3.Cluster>` to create a user space
        /// connection to. The internal listener acts as a tcp listener. It supports
        /// listener filters and network filter chains. The internal listener require
        /// :ref:`address <envoy_v3_api_field_config.listener.v3.Listener.address>`
        /// has field `envoy_internal_address`.
        ///
        /// There are some limitations are derived from the implementation. The known
        /// limitations include
        ///
        /// * :ref:`ConnectionBalanceConfig
        /// <envoy_v3_api_msg_config.listener.v3.Listener.ConnectionBalanceConfig>`
        /// is not
        ///```ignore
        ///    allowed because both cluster connection and listener connection must be
        ///    owned by the same dispatcher.
        ///```
        /// * :ref:`tcp_backlog_size
        /// <envoy_v3_api_field_config.listener.v3.Listener.tcp_backlog_size>`
        /// * :ref:`freebind
        /// <envoy_v3_api_field_config.listener.v3.Listener.freebind>`
        /// * :ref:`transparent
        /// <envoy_v3_api_field_config.listener.v3.Listener.transparent>`
        /// \[#not-implemented-hide:\]
        #[prost(message, tag = "27")]
        InternalListener(InternalListenerConfig),
    }
}
