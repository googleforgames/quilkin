/// Describes custom tags for the active span.
/// \[#next-free-field: 6\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CustomTag {
    /// Used to populate the tag name.
    #[prost(string, tag = "1")]
    pub tag: ::prost::alloc::string::String,
    /// Used to specify what kind of custom tag.
    #[prost(oneof = "custom_tag::Type", tags = "2, 3, 4, 5")]
    pub r#type: ::core::option::Option<custom_tag::Type>,
}
/// Nested message and enum types in `CustomTag`.
pub mod custom_tag {
    /// Literal type custom tag with static value for the tag value.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Literal {
        /// Static literal value to populate the tag value.
        #[prost(string, tag = "1")]
        pub value: ::prost::alloc::string::String,
    }
    /// Environment type custom tag with environment name and default value.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Environment {
        /// Environment variable name to obtain the value to populate the tag value.
        #[prost(string, tag = "1")]
        pub name: ::prost::alloc::string::String,
        /// When the environment variable is not found,
        /// the tag value will be populated with this default value if specified,
        /// otherwise no tag will be populated.
        #[prost(string, tag = "2")]
        pub default_value: ::prost::alloc::string::String,
    }
    /// Header type custom tag with header name and default value.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Header {
        /// Header name to obtain the value to populate the tag value.
        #[prost(string, tag = "1")]
        pub name: ::prost::alloc::string::String,
        /// When the header does not exist,
        /// the tag value will be populated with this default value if specified,
        /// otherwise no tag will be populated.
        #[prost(string, tag = "2")]
        pub default_value: ::prost::alloc::string::String,
    }
    /// Metadata type custom tag using
    /// :ref:`MetadataKey <envoy_v3_api_msg_type.metadata.v3.MetadataKey>` to
    /// retrieve the protobuf value from :ref:`Metadata
    /// <envoy_v3_api_msg_config.core.v3.Metadata>`, and populate the tag value
    /// with `the canonical JSON
    /// <<https://developers.google.com/protocol-buffers/docs/proto3#json>`_>
    /// representation of it.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Metadata {
        /// Specify what kind of metadata to obtain tag value from.
        #[prost(message, optional, tag = "1")]
        pub kind: ::core::option::Option<
            super::super::super::metadata::v3::MetadataKind,
        >,
        /// Metadata key to define the path to retrieve the tag value.
        #[prost(message, optional, tag = "2")]
        pub metadata_key: ::core::option::Option<
            super::super::super::metadata::v3::MetadataKey,
        >,
        /// When no valid metadata is found,
        /// the tag value would be populated with this default value if specified,
        /// otherwise no tag would be populated.
        #[prost(string, tag = "3")]
        pub default_value: ::prost::alloc::string::String,
    }
    /// Used to specify what kind of custom tag.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Type {
        /// A literal custom tag.
        #[prost(message, tag = "2")]
        Literal(Literal),
        /// An environment custom tag.
        #[prost(message, tag = "3")]
        Environment(Environment),
        /// A request header custom tag.
        #[prost(message, tag = "4")]
        RequestHeader(Header),
        /// A custom tag to obtain tag value from the metadata.
        #[prost(message, tag = "5")]
        Metadata(Metadata),
    }
}
