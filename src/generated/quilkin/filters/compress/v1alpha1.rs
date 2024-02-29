#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Compress {
    #[prost(message, optional, tag = "1")]
    pub mode: ::core::option::Option<compress::ModeValue>,
    #[prost(message, optional, tag = "2")]
    pub on_read: ::core::option::Option<compress::ActionValue>,
    #[prost(message, optional, tag = "3")]
    pub on_write: ::core::option::Option<compress::ActionValue>,
}
/// Nested message and enum types in `Compress`.
pub mod compress {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ModeValue {
        #[prost(enumeration = "Mode", tag = "1")]
        pub value: i32,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ActionValue {
        #[prost(enumeration = "Action", tag = "1")]
        pub value: i32,
    }
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
    pub enum Mode {
        Snappy = 0,
        Lz4 = 1,
    }
    impl Mode {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Mode::Snappy => "Snappy",
                Mode::Lz4 => "Lz4",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "Snappy" => Some(Self::Snappy),
                "Lz4" => Some(Self::Lz4),
                _ => None,
            }
        }
    }
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
    pub enum Action {
        DoNothing = 0,
        Compress = 1,
        Decompress = 2,
    }
    impl Action {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Action::DoNothing => "DoNothing",
                Action::Compress => "Compress",
                Action::Decompress => "Decompress",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "DoNothing" => Some(Self::DoNothing),
                "Compress" => Some(Self::Compress),
                "Decompress" => Some(Self::Decompress),
                _ => None,
            }
        }
    }
}
