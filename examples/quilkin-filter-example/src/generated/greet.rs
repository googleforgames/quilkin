#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Greet {
    #[prost(string, tag = "1")]
    pub greeting: ::prost::alloc::string::String,
}
