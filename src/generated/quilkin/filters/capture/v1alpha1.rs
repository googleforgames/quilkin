#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Capture {
    #[prost(message, optional, tag = "1")]
    pub metadata_key: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(oneof = "capture::Strategy", tags = "2, 3, 4")]
    pub strategy: ::core::option::Option<capture::Strategy>,
}
/// Nested message and enum types in `Capture`.
pub mod capture {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Suffix {
        #[prost(uint32, tag = "1")]
        pub size: u32,
        #[prost(message, optional, tag = "2")]
        pub remove: ::core::option::Option<bool>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Prefix {
        #[prost(uint32, tag = "1")]
        pub size: u32,
        #[prost(message, optional, tag = "2")]
        pub remove: ::core::option::Option<bool>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Regex {
        #[prost(message, optional, tag = "1")]
        pub regex: ::core::option::Option<::prost::alloc::string::String>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Strategy {
        #[prost(message, tag = "2")]
        Prefix(Prefix),
        #[prost(message, tag = "3")]
        Suffix(Suffix),
        #[prost(message, tag = "4")]
        Regex(Regex),
    }
}
