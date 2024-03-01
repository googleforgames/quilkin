#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TypedExtensionConfig {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub typed_config: ::core::option::Option<::prost_types::Any>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Authority {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContextParams {
    #[prost(map = "string, string", tag = "1")]
    pub params:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResourceLocator {
    #[prost(enumeration = "resource_locator::Scheme", tag = "1")]
    pub scheme: i32,
    #[prost(string, tag = "2")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub authority: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub resource_type: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "6")]
    pub directives: ::prost::alloc::vec::Vec<resource_locator::Directive>,
    #[prost(oneof = "resource_locator::ContextParamSpecifier", tags = "5")]
    pub context_param_specifier: ::core::option::Option<resource_locator::ContextParamSpecifier>,
}
/// Nested message and enum types in `ResourceLocator`.
pub mod resource_locator {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Directive {
        #[prost(oneof = "directive::Directive", tags = "1, 2")]
        pub directive: ::core::option::Option<directive::Directive>,
    }
    /// Nested message and enum types in `Directive`.
    pub mod directive {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Directive {
            #[prost(message, tag = "1")]
            Alt(super::super::ResourceLocator),
            #[prost(string, tag = "2")]
            Entry(::prost::alloc::string::String),
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Scheme {
        Xdstp = 0,
        Http = 1,
        File = 2,
    }
    impl Scheme {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Scheme::Xdstp => "XDSTP",
                Scheme::Http => "HTTP",
                Scheme::File => "FILE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "XDSTP" => Some(Self::Xdstp),
                "HTTP" => Some(Self::Http),
                "FILE" => Some(Self::File),
                _ => None,
            }
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ContextParamSpecifier {
        #[prost(message, tag = "5")]
        ExactContext(super::ContextParams),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CollectionEntry {
    #[prost(oneof = "collection_entry::ResourceSpecifier", tags = "1, 2")]
    pub resource_specifier: ::core::option::Option<collection_entry::ResourceSpecifier>,
}
/// Nested message and enum types in `CollectionEntry`.
pub mod collection_entry {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct InlineEntry {
        #[prost(string, tag = "1")]
        pub name: ::prost::alloc::string::String,
        #[prost(string, tag = "2")]
        pub version: ::prost::alloc::string::String,
        #[prost(message, optional, tag = "3")]
        pub resource: ::core::option::Option<::prost_types::Any>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ResourceSpecifier {
        #[prost(message, tag = "1")]
        Locator(super::ResourceLocator),
        #[prost(message, tag = "2")]
        InlineEntry(InlineEntry),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ResourceName {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub authority: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub resource_type: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "4")]
    pub context: ::core::option::Option<ContextParams>,
}
