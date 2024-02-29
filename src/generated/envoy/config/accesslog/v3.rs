#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccessLog {
    /// The name of the access log extension to instantiate.
    /// The name must match one of the compiled in loggers.
    /// See the :ref:`extensions listed in typed_config below
    /// <extension_category_envoy.access_loggers>` for the default list of
    /// available loggers.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Filter which is used to determine if the access log needs to be written.
    #[prost(message, optional, tag = "2")]
    pub filter: ::core::option::Option<AccessLogFilter>,
    /// Custom configuration that must be set according to the access logger
    /// extension being instantiated.
    /// \[#extension-category: envoy.access_loggers\]
    #[prost(oneof = "access_log::ConfigType", tags = "4")]
    pub config_type: ::core::option::Option<access_log::ConfigType>,
}
/// Nested message and enum types in `AccessLog`.
pub mod access_log {
    /// Custom configuration that must be set according to the access logger
    /// extension being instantiated.
    /// \[#extension-category: envoy.access_loggers\]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ConfigType {
        #[prost(message, tag = "4")]
        TypedConfig(::prost_types::Any),
    }
}
/// \[#next-free-field: 13\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccessLogFilter {
    #[prost(
        oneof = "access_log_filter::FilterSpecifier",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12"
    )]
    pub filter_specifier: ::core::option::Option<access_log_filter::FilterSpecifier>,
}
/// Nested message and enum types in `AccessLogFilter`.
pub mod access_log_filter {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum FilterSpecifier {
        /// Status code filter.
        #[prost(message, tag = "1")]
        StatusCodeFilter(super::StatusCodeFilter),
        /// Duration filter.
        #[prost(message, tag = "2")]
        DurationFilter(super::DurationFilter),
        /// Not health check filter.
        #[prost(message, tag = "3")]
        NotHealthCheckFilter(super::NotHealthCheckFilter),
        /// Traceable filter.
        #[prost(message, tag = "4")]
        TraceableFilter(super::TraceableFilter),
        /// Runtime filter.
        #[prost(message, tag = "5")]
        RuntimeFilter(super::RuntimeFilter),
        /// And filter.
        #[prost(message, tag = "6")]
        AndFilter(super::AndFilter),
        /// Or filter.
        #[prost(message, tag = "7")]
        OrFilter(super::OrFilter),
        /// Header filter.
        #[prost(message, tag = "8")]
        HeaderFilter(super::HeaderFilter),
        /// Response flag filter.
        #[prost(message, tag = "9")]
        ResponseFlagFilter(super::ResponseFlagFilter),
        /// gRPC status filter.
        #[prost(message, tag = "10")]
        GrpcStatusFilter(super::GrpcStatusFilter),
        /// Extension filter.
        /// \[#extension-category: envoy.access_loggers.extension_filters\]
        #[prost(message, tag = "11")]
        ExtensionFilter(super::ExtensionFilter),
        /// Metadata Filter
        #[prost(message, tag = "12")]
        MetadataFilter(super::MetadataFilter),
    }
}
/// Filter on an integer comparison.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ComparisonFilter {
    /// Comparison operator.
    #[prost(enumeration = "comparison_filter::Op", tag = "1")]
    pub op: i32,
    /// Value to compare against.
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<super::super::core::v3::RuntimeUInt32>,
}
/// Nested message and enum types in `ComparisonFilter`.
pub mod comparison_filter {
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
    pub enum Op {
        /// =
        Eq = 0,
        /// >=
        Ge = 1,
        /// <=
        Le = 2,
    }
    impl Op {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Op::Eq => "EQ",
                Op::Ge => "GE",
                Op::Le => "LE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "EQ" => Some(Self::Eq),
                "GE" => Some(Self::Ge),
                "LE" => Some(Self::Le),
                _ => None,
            }
        }
    }
}
/// Filters on HTTP response/status code.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatusCodeFilter {
    /// Comparison.
    #[prost(message, optional, tag = "1")]
    pub comparison: ::core::option::Option<ComparisonFilter>,
}
/// Filters on total request duration in milliseconds.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DurationFilter {
    /// Comparison.
    #[prost(message, optional, tag = "1")]
    pub comparison: ::core::option::Option<ComparisonFilter>,
}
/// Filters for requests that are not health check requests. A health check
/// request is marked by the health check filter.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NotHealthCheckFilter {}
/// Filters for requests that are traceable. See the tracing overview for more
/// information on how a request becomes traceable.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TraceableFilter {}
/// Filters for random sampling of requests.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuntimeFilter {
    /// Runtime key to get an optional overridden numerator for use in the
    /// *percent_sampled* field. If found in runtime, this value will replace the
    /// default numerator.
    #[prost(string, tag = "1")]
    pub runtime_key: ::prost::alloc::string::String,
    /// The default sampling percentage. If not specified, defaults to 0% with
    /// denominator of 100.
    #[prost(message, optional, tag = "2")]
    pub percent_sampled: ::core::option::Option<
        super::super::super::kind::v3::FractionalPercent,
    >,
    /// By default, sampling pivots on the header
    /// :ref:`x-request-id<config_http_conn_man_headers_x-request-id>` being
    /// present. If :ref:`x-request-id<config_http_conn_man_headers_x-request-id>`
    /// is present, the filter will consistently sample across multiple hosts based
    /// on the runtime key value and the value extracted from
    /// :ref:`x-request-id<config_http_conn_man_headers_x-request-id>`. If it is
    /// missing, or *use_independent_randomness* is set to true, the filter will
    /// randomly sample based on the runtime key value alone.
    /// *use_independent_randomness* can be used for logging kill switches within
    /// complex nested :ref:`AndFilter
    /// <envoy_v3_api_msg_config.accesslog.v3.AndFilter>` and :ref:`OrFilter
    /// <envoy_v3_api_msg_config.accesslog.v3.OrFilter>` blocks that are easier to
    /// reason about from a probability perspective (i.e., setting to true will
    /// cause the filter to behave like an independent random variable when
    /// composed within logical operator filters).
    #[prost(bool, tag = "3")]
    pub use_independent_randomness: bool,
}
/// Performs a logical “and” operation on the result of each filter in filters.
/// Filters are evaluated sequentially and if one of them returns false, the
/// filter returns false immediately.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AndFilter {
    #[prost(message, repeated, tag = "1")]
    pub filters: ::prost::alloc::vec::Vec<AccessLogFilter>,
}
/// Performs a logical “or” operation on the result of each individual filter.
/// Filters are evaluated sequentially and if one of them returns true, the
/// filter returns true immediately.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OrFilter {
    #[prost(message, repeated, tag = "2")]
    pub filters: ::prost::alloc::vec::Vec<AccessLogFilter>,
}
/// Filters requests based on the presence or value of a request header.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HeaderFilter {
    /// Only requests with a header which matches the specified HeaderMatcher will
    /// pass the filter check.
    #[prost(message, optional, tag = "1")]
    pub header: ::core::option::Option<super::super::route::v3::HeaderMatcher>,
}
/// Filters requests that received responses with an Envoy response flag set.
/// A list of the response flags can be found
/// in the access log formatter
/// :ref:`documentation<config_access_log_format_response_flags>`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResponseFlagFilter {
    /// Only responses with the any of the flags listed in this field will be
    /// logged. This field is optional. If it is not specified, then any response
    /// flag will pass the filter check.
    #[prost(string, repeated, tag = "1")]
    pub flags: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// Filters gRPC requests based on their response status. If a gRPC status is not
/// provided, the filter will infer the status from the HTTP status code.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GrpcStatusFilter {
    /// Logs only responses that have any one of the gRPC statuses in this field.
    #[prost(
        enumeration = "grpc_status_filter::Status",
        repeated,
        packed = "false",
        tag = "1"
    )]
    pub statuses: ::prost::alloc::vec::Vec<i32>,
    /// If included and set to true, the filter will instead block all responses
    /// with a gRPC status or inferred gRPC status enumerated in statuses, and
    /// allow all other responses.
    #[prost(bool, tag = "2")]
    pub exclude: bool,
}
/// Nested message and enum types in `GrpcStatusFilter`.
pub mod grpc_status_filter {
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
    pub enum Status {
        Ok = 0,
        Canceled = 1,
        Unknown = 2,
        InvalidArgument = 3,
        DeadlineExceeded = 4,
        NotFound = 5,
        AlreadyExists = 6,
        PermissionDenied = 7,
        ResourceExhausted = 8,
        FailedPrecondition = 9,
        Aborted = 10,
        OutOfRange = 11,
        Unimplemented = 12,
        Internal = 13,
        Unavailable = 14,
        DataLoss = 15,
        Unauthenticated = 16,
    }
    impl Status {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Status::Ok => "OK",
                Status::Canceled => "CANCELED",
                Status::Unknown => "UNKNOWN",
                Status::InvalidArgument => "INVALID_ARGUMENT",
                Status::DeadlineExceeded => "DEADLINE_EXCEEDED",
                Status::NotFound => "NOT_FOUND",
                Status::AlreadyExists => "ALREADY_EXISTS",
                Status::PermissionDenied => "PERMISSION_DENIED",
                Status::ResourceExhausted => "RESOURCE_EXHAUSTED",
                Status::FailedPrecondition => "FAILED_PRECONDITION",
                Status::Aborted => "ABORTED",
                Status::OutOfRange => "OUT_OF_RANGE",
                Status::Unimplemented => "UNIMPLEMENTED",
                Status::Internal => "INTERNAL",
                Status::Unavailable => "UNAVAILABLE",
                Status::DataLoss => "DATA_LOSS",
                Status::Unauthenticated => "UNAUTHENTICATED",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "OK" => Some(Self::Ok),
                "CANCELED" => Some(Self::Canceled),
                "UNKNOWN" => Some(Self::Unknown),
                "INVALID_ARGUMENT" => Some(Self::InvalidArgument),
                "DEADLINE_EXCEEDED" => Some(Self::DeadlineExceeded),
                "NOT_FOUND" => Some(Self::NotFound),
                "ALREADY_EXISTS" => Some(Self::AlreadyExists),
                "PERMISSION_DENIED" => Some(Self::PermissionDenied),
                "RESOURCE_EXHAUSTED" => Some(Self::ResourceExhausted),
                "FAILED_PRECONDITION" => Some(Self::FailedPrecondition),
                "ABORTED" => Some(Self::Aborted),
                "OUT_OF_RANGE" => Some(Self::OutOfRange),
                "UNIMPLEMENTED" => Some(Self::Unimplemented),
                "INTERNAL" => Some(Self::Internal),
                "UNAVAILABLE" => Some(Self::Unavailable),
                "DATA_LOSS" => Some(Self::DataLoss),
                "UNAUTHENTICATED" => Some(Self::Unauthenticated),
                _ => None,
            }
        }
    }
}
/// Filters based on matching dynamic metadata.
/// If the matcher path and key correspond to an existing key in dynamic
/// metadata, the request is logged only if the matcher value is equal to the
/// metadata value. If the matcher path and key *do not* correspond to an
/// existing key in dynamic metadata, the request is logged only if
/// match_if_key_not_found is "true" or unset.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetadataFilter {
    /// Matcher to check metadata for specified value. For example, to match on the
    /// access_log_hint metadata, set the filter to "envoy.common" and the path to
    /// "access_log_hint", and the value to "true".
    #[prost(message, optional, tag = "1")]
    pub matcher: ::core::option::Option<
        super::super::super::kind::matcher::v3::MetadataMatcher,
    >,
    /// Default result if the key does not exist in dynamic metadata: if unset or
    /// true, then log; if false, then don't log.
    #[prost(message, optional, tag = "2")]
    pub match_if_key_not_found: ::core::option::Option<bool>,
}
/// Extension filter is statically registered at runtime.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExtensionFilter {
    /// The name of the filter implementation to instantiate. The name must
    /// match a statically registered filter.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Custom configuration that depends on the filter being instantiated.
    #[prost(oneof = "extension_filter::ConfigType", tags = "3")]
    pub config_type: ::core::option::Option<extension_filter::ConfigType>,
}
/// Nested message and enum types in `ExtensionFilter`.
pub mod extension_filter {
    /// Custom configuration that depends on the filter being instantiated.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ConfigType {
        #[prost(message, tag = "3")]
        TypedConfig(::prost_types::Any),
    }
}
