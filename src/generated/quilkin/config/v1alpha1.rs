#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClusterMap {
    #[prost(message, repeated, tag = "1")]
    pub clusters: ::prost::alloc::vec::Vec<Cluster>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Cluster {
    #[prost(message, optional, tag = "1")]
    pub locality: ::core::option::Option<Locality>,
    #[prost(message, repeated, tag = "2")]
    pub endpoints: ::prost::alloc::vec::Vec<Endpoint>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Locality {
    #[prost(string, tag = "1")]
    pub region: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub zone: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub sub_zone: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Endpoint {
    #[prost(string, tag = "1")]
    pub host: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub port: u32,
    #[prost(message, optional, tag = "3")]
    pub metadata: ::core::option::Option<::prost_types::Struct>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Datacenter {
    #[prost(string, tag = "1")]
    pub host: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub qcmp_port: u32,
    #[prost(string, tag = "3")]
    pub icao_code: ::prost::alloc::string::String,
}
