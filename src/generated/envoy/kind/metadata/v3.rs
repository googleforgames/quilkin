/// MetadataKey provides a general interface using `key` and `path` to retrieve
/// value from :ref:`Metadata <envoy_v3_api_msg_config.core.v3.Metadata>`.
///
/// For example, for the following Metadata:
///
/// .. code-block:: yaml
///
///```ignore
///     filter_metadata:
///       envoy.xxx:
///         prop:
///           foo: bar
///           xyz:
///             hello: envoy
///```
///
/// The following MetadataKey will retrieve a string value "bar" from the
/// Metadata.
///
/// .. code-block:: yaml
///
///```ignore
///     key: envoy.xxx
///     path:
///     - key: prop
///     - key: foo
///```
///
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetadataKey {
    /// The key name of Metadata to retrieve the Struct from the metadata.
    /// Typically, it represents a builtin subsystem or custom extension.
    #[prost(string, tag = "1")]
    pub key: ::prost::alloc::string::String,
    /// The path to retrieve the Value from the Struct. It can be a prefix or a
    /// full path, e.g. ``\[prop, xyz\]`` for a struct or ``\[prop, foo\]`` for a
    /// string in the example, which depends on the particular scenario.
    ///
    /// Note: Due to that only the key type segment is supported, the path can not
    /// specify a list unless the list is the last segment.
    #[prost(message, repeated, tag = "2")]
    pub path: ::prost::alloc::vec::Vec<metadata_key::PathSegment>,
}
/// Nested message and enum types in `MetadataKey`.
pub mod metadata_key {
    /// Specifies the segment in a path to retrieve value from Metadata.
    /// Currently it is only supported to specify the key, i.e. field name, as one
    /// segment of a path.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PathSegment {
        #[prost(oneof = "path_segment::Segment", tags = "1")]
        pub segment: ::core::option::Option<path_segment::Segment>,
    }
    /// Nested message and enum types in `PathSegment`.
    pub mod path_segment {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Segment {
            /// If specified, use the key to retrieve the value in a Struct.
            #[prost(string, tag = "1")]
            Key(::prost::alloc::string::String),
        }
    }
}
/// Describes what kind of metadata.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetadataKind {
    #[prost(oneof = "metadata_kind::Kind", tags = "1, 2, 3, 4")]
    pub kind: ::core::option::Option<metadata_kind::Kind>,
}
/// Nested message and enum types in `MetadataKind`.
pub mod metadata_kind {
    /// Represents dynamic metadata associated with the request.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Request {}
    /// Represents metadata from :ref:`the
    /// route<envoy_v3_api_field_config.route.v3.Route.metadata>`.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Route {}
    /// Represents metadata from :ref:`the upstream
    /// cluster<envoy_v3_api_field_config.cluster.v3.Cluster.metadata>`.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Cluster {}
    /// Represents metadata from :ref:`the upstream
    /// host<envoy_v3_api_field_config.endpoint.v3.LbEndpoint.metadata>`.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Host {}
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Request kind of metadata.
        #[prost(message, tag = "1")]
        Request(Request),
        /// Route kind of metadata.
        #[prost(message, tag = "2")]
        Route(Route),
        /// Cluster kind of metadata.
        #[prost(message, tag = "3")]
        Cluster(Cluster),
        /// Host kind of metadata.
        #[prost(message, tag = "4")]
        Host(Host),
    }
}
