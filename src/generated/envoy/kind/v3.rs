/// Identifies a percentage, in the range \[0.0, 100.0\].
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Percent {
    #[prost(double, tag = "1")]
    pub value: f64,
}
/// A fractional percentage is used in cases in which for performance reasons
/// performing floating point to integer conversions during randomness
/// calculations is undesirable. The message includes both a numerator and
/// denominator that together determine the final fractional value.
///
/// * **Example**: 1/100 = 1%.
/// * **Example**: 3/10000 = 0.03%.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FractionalPercent {
    /// Specifies the numerator. Defaults to 0.
    #[prost(uint32, tag = "1")]
    pub numerator: u32,
    /// Specifies the denominator. If the denominator specified is less than the
    /// numerator, the final fractional percentage is capped at 1 (100%).
    #[prost(enumeration = "fractional_percent::DenominatorType", tag = "2")]
    pub denominator: i32,
}
/// Nested message and enum types in `FractionalPercent`.
pub mod fractional_percent {
    /// Fraction percentages support several fixed denominator values.
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
    pub enum DenominatorType {
        /// 100.
        ///
        /// **Example**: 1/100 = 1%.
        Hundred = 0,
        /// 10,000.
        ///
        /// **Example**: 1/10000 = 0.01%.
        TenThousand = 1,
        /// 1,000,000.
        ///
        /// **Example**: 1/1000000 = 0.0001%.
        Million = 2,
    }
    impl DenominatorType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                DenominatorType::Hundred => "HUNDRED",
                DenominatorType::TenThousand => "TEN_THOUSAND",
                DenominatorType::Million => "MILLION",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "HUNDRED" => Some(Self::Hundred),
                "TEN_THOUSAND" => Some(Self::TenThousand),
                "MILLION" => Some(Self::Million),
                _ => None,
            }
        }
    }
}
/// Specifies the int64 start and end of the range using half-open interval
/// semantics [start, end).
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Int64Range {
    /// start of the range (inclusive)
    #[prost(int64, tag = "1")]
    pub start: i64,
    /// end of the range (exclusive)
    #[prost(int64, tag = "2")]
    pub end: i64,
}
/// Specifies the int32 start and end of the range using half-open interval
/// semantics [start, end).
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Int32Range {
    /// start of the range (inclusive)
    #[prost(int32, tag = "1")]
    pub start: i32,
    /// end of the range (exclusive)
    #[prost(int32, tag = "2")]
    pub end: i32,
}
/// Specifies the double start and end of the range using half-open interval
/// semantics [start, end).
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DoubleRange {
    /// start of the range (inclusive)
    #[prost(double, tag = "1")]
    pub start: f64,
    /// end of the range (exclusive)
    #[prost(double, tag = "2")]
    pub end: f64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CodecClientType {
    Http1 = 0,
    Http2 = 1,
    /// \[#not-implemented-hide:\] QUIC implementation is not production ready yet.
    /// Use this enum with caution to prevent accidental execution of QUIC code.
    /// I.e. `!= HTTP2` is no longer sufficient to distinguish HTTP1 and HTTP2
    /// traffic.
    Http3 = 2,
}
impl CodecClientType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            CodecClientType::Http1 => "HTTP1",
            CodecClientType::Http2 => "HTTP2",
            CodecClientType::Http3 => "HTTP3",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "HTTP1" => Some(Self::Http1),
            "HTTP2" => Some(Self::Http2),
            "HTTP3" => Some(Self::Http3),
            _ => None,
        }
    }
}
