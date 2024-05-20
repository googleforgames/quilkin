#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LocalRateLimit {
    #[prost(uint64, tag = "1")]
    pub max_packets: u64,
    #[prost(message, optional, tag = "2")]
    pub period: ::core::option::Option<u32>,
}
