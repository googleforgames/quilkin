/// FieldRules encapsulates the rules for each type of field. Depending on the
/// field, the correct set should be used to ensure proper validations.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FieldRules {
    #[prost(message, optional, tag = "17")]
    pub message: ::core::option::Option<MessageRules>,
    #[prost(
        oneof = "field_rules::Type",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22"
    )]
    pub r#type: ::core::option::Option<field_rules::Type>,
}
/// Nested message and enum types in `FieldRules`.
pub mod field_rules {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Type {
        /// Scalar Field Types
        #[prost(message, tag = "1")]
        Float(super::FloatRules),
        #[prost(message, tag = "2")]
        Double(super::DoubleRules),
        #[prost(message, tag = "3")]
        Int32(super::Int32Rules),
        #[prost(message, tag = "4")]
        Int64(super::Int64Rules),
        #[prost(message, tag = "5")]
        Uint32(super::UInt32Rules),
        #[prost(message, tag = "6")]
        Uint64(super::UInt64Rules),
        #[prost(message, tag = "7")]
        Sint32(super::SInt32Rules),
        #[prost(message, tag = "8")]
        Sint64(super::SInt64Rules),
        #[prost(message, tag = "9")]
        Fixed32(super::Fixed32Rules),
        #[prost(message, tag = "10")]
        Fixed64(super::Fixed64Rules),
        #[prost(message, tag = "11")]
        Sfixed32(super::SFixed32Rules),
        #[prost(message, tag = "12")]
        Sfixed64(super::SFixed64Rules),
        #[prost(message, tag = "13")]
        Bool(super::BoolRules),
        #[prost(message, tag = "14")]
        String(super::StringRules),
        #[prost(message, tag = "15")]
        Bytes(super::BytesRules),
        /// Complex Field Types
        #[prost(message, tag = "16")]
        Enum(super::EnumRules),
        #[prost(message, tag = "18")]
        Repeated(::prost::alloc::boxed::Box<super::RepeatedRules>),
        #[prost(message, tag = "19")]
        Map(::prost::alloc::boxed::Box<super::MapRules>),
        /// Well-Known Field Types
        #[prost(message, tag = "20")]
        Any(super::AnyRules),
        #[prost(message, tag = "21")]
        Duration(super::DurationRules),
        #[prost(message, tag = "22")]
        Timestamp(super::TimestampRules),
    }
}
/// FloatRules describes the constraints applied to `float` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FloatRules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(float, optional, tag = "1")]
    pub r#const: ::core::option::Option<f32>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(float, optional, tag = "2")]
    pub lt: ::core::option::Option<f32>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(float, optional, tag = "3")]
    pub lte: ::core::option::Option<f32>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(float, optional, tag = "4")]
    pub gt: ::core::option::Option<f32>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(float, optional, tag = "5")]
    pub gte: ::core::option::Option<f32>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(float, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<f32>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(float, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<f32>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// DoubleRules describes the constraints applied to `double` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DoubleRules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(double, optional, tag = "1")]
    pub r#const: ::core::option::Option<f64>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(double, optional, tag = "2")]
    pub lt: ::core::option::Option<f64>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(double, optional, tag = "3")]
    pub lte: ::core::option::Option<f64>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(double, optional, tag = "4")]
    pub gt: ::core::option::Option<f64>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(double, optional, tag = "5")]
    pub gte: ::core::option::Option<f64>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(double, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<f64>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(double, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<f64>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// Int32Rules describes the constraints applied to `int32` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Int32Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(int32, optional, tag = "1")]
    pub r#const: ::core::option::Option<i32>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(int32, optional, tag = "2")]
    pub lt: ::core::option::Option<i32>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(int32, optional, tag = "3")]
    pub lte: ::core::option::Option<i32>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(int32, optional, tag = "4")]
    pub gt: ::core::option::Option<i32>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(int32, optional, tag = "5")]
    pub gte: ::core::option::Option<i32>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(int32, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<i32>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(int32, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<i32>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// Int64Rules describes the constraints applied to `int64` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Int64Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(int64, optional, tag = "1")]
    pub r#const: ::core::option::Option<i64>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(int64, optional, tag = "2")]
    pub lt: ::core::option::Option<i64>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(int64, optional, tag = "3")]
    pub lte: ::core::option::Option<i64>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(int64, optional, tag = "4")]
    pub gt: ::core::option::Option<i64>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(int64, optional, tag = "5")]
    pub gte: ::core::option::Option<i64>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(int64, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<i64>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(int64, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<i64>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// UInt32Rules describes the constraints applied to `uint32` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UInt32Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(uint32, optional, tag = "1")]
    pub r#const: ::core::option::Option<u32>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(uint32, optional, tag = "2")]
    pub lt: ::core::option::Option<u32>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(uint32, optional, tag = "3")]
    pub lte: ::core::option::Option<u32>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(uint32, optional, tag = "4")]
    pub gt: ::core::option::Option<u32>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(uint32, optional, tag = "5")]
    pub gte: ::core::option::Option<u32>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(uint32, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<u32>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(uint32, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<u32>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// UInt64Rules describes the constraints applied to `uint64` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UInt64Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(uint64, optional, tag = "1")]
    pub r#const: ::core::option::Option<u64>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(uint64, optional, tag = "2")]
    pub lt: ::core::option::Option<u64>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(uint64, optional, tag = "3")]
    pub lte: ::core::option::Option<u64>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(uint64, optional, tag = "4")]
    pub gt: ::core::option::Option<u64>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(uint64, optional, tag = "5")]
    pub gte: ::core::option::Option<u64>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(uint64, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<u64>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(uint64, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<u64>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// SInt32Rules describes the constraints applied to `sint32` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SInt32Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(sint32, optional, tag = "1")]
    pub r#const: ::core::option::Option<i32>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(sint32, optional, tag = "2")]
    pub lt: ::core::option::Option<i32>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(sint32, optional, tag = "3")]
    pub lte: ::core::option::Option<i32>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(sint32, optional, tag = "4")]
    pub gt: ::core::option::Option<i32>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(sint32, optional, tag = "5")]
    pub gte: ::core::option::Option<i32>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(sint32, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<i32>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(sint32, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<i32>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// SInt64Rules describes the constraints applied to `sint64` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SInt64Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(sint64, optional, tag = "1")]
    pub r#const: ::core::option::Option<i64>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(sint64, optional, tag = "2")]
    pub lt: ::core::option::Option<i64>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(sint64, optional, tag = "3")]
    pub lte: ::core::option::Option<i64>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(sint64, optional, tag = "4")]
    pub gt: ::core::option::Option<i64>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(sint64, optional, tag = "5")]
    pub gte: ::core::option::Option<i64>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(sint64, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<i64>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(sint64, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<i64>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// Fixed32Rules describes the constraints applied to `fixed32` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fixed32Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(fixed32, optional, tag = "1")]
    pub r#const: ::core::option::Option<u32>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(fixed32, optional, tag = "2")]
    pub lt: ::core::option::Option<u32>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(fixed32, optional, tag = "3")]
    pub lte: ::core::option::Option<u32>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(fixed32, optional, tag = "4")]
    pub gt: ::core::option::Option<u32>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(fixed32, optional, tag = "5")]
    pub gte: ::core::option::Option<u32>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(fixed32, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<u32>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(fixed32, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<u32>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// Fixed64Rules describes the constraints applied to `fixed64` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fixed64Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(fixed64, optional, tag = "1")]
    pub r#const: ::core::option::Option<u64>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(fixed64, optional, tag = "2")]
    pub lt: ::core::option::Option<u64>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(fixed64, optional, tag = "3")]
    pub lte: ::core::option::Option<u64>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(fixed64, optional, tag = "4")]
    pub gt: ::core::option::Option<u64>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(fixed64, optional, tag = "5")]
    pub gte: ::core::option::Option<u64>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(fixed64, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<u64>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(fixed64, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<u64>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// SFixed32Rules describes the constraints applied to `sfixed32` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SFixed32Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(sfixed32, optional, tag = "1")]
    pub r#const: ::core::option::Option<i32>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(sfixed32, optional, tag = "2")]
    pub lt: ::core::option::Option<i32>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(sfixed32, optional, tag = "3")]
    pub lte: ::core::option::Option<i32>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(sfixed32, optional, tag = "4")]
    pub gt: ::core::option::Option<i32>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(sfixed32, optional, tag = "5")]
    pub gte: ::core::option::Option<i32>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(sfixed32, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<i32>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(sfixed32, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<i32>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// SFixed64Rules describes the constraints applied to `sfixed64` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SFixed64Rules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(sfixed64, optional, tag = "1")]
    pub r#const: ::core::option::Option<i64>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(sfixed64, optional, tag = "2")]
    pub lt: ::core::option::Option<i64>,
    /// Lte specifies that this field must be less than or equal to the
    /// specified value, inclusive
    #[prost(sfixed64, optional, tag = "3")]
    pub lte: ::core::option::Option<i64>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive. If the value of Gt is larger than a specified Lt or Lte, the
    /// range is reversed.
    #[prost(sfixed64, optional, tag = "4")]
    pub gt: ::core::option::Option<i64>,
    /// Gte specifies that this field must be greater than or equal to the
    /// specified value, inclusive. If the value of Gte is larger than a
    /// specified Lt or Lte, the range is reversed.
    #[prost(sfixed64, optional, tag = "5")]
    pub gte: ::core::option::Option<i64>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(sfixed64, repeated, packed = "false", tag = "6")]
    pub r#in: ::prost::alloc::vec::Vec<i64>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(sfixed64, repeated, packed = "false", tag = "7")]
    pub not_in: ::prost::alloc::vec::Vec<i64>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "8")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// BoolRules describes the constraints applied to `bool` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BoolRules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(bool, optional, tag = "1")]
    pub r#const: ::core::option::Option<bool>,
}
/// StringRules describe the constraints applied to `string` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringRules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(string, optional, tag = "1")]
    pub r#const: ::core::option::Option<::prost::alloc::string::String>,
    /// Len specifies that this field must be the specified number of
    /// characters (Unicode code points). Note that the number of
    /// characters may differ from the number of bytes in the string.
    #[prost(uint64, optional, tag = "19")]
    pub len: ::core::option::Option<u64>,
    /// MinLen specifies that this field must be the specified number of
    /// characters (Unicode code points) at a minimum. Note that the number of
    /// characters may differ from the number of bytes in the string.
    #[prost(uint64, optional, tag = "2")]
    pub min_len: ::core::option::Option<u64>,
    /// MaxLen specifies that this field must be the specified number of
    /// characters (Unicode code points) at a maximum. Note that the number of
    /// characters may differ from the number of bytes in the string.
    #[prost(uint64, optional, tag = "3")]
    pub max_len: ::core::option::Option<u64>,
    /// LenBytes specifies that this field must be the specified number of bytes
    #[prost(uint64, optional, tag = "20")]
    pub len_bytes: ::core::option::Option<u64>,
    /// MinBytes specifies that this field must be the specified number of bytes
    /// at a minimum
    #[prost(uint64, optional, tag = "4")]
    pub min_bytes: ::core::option::Option<u64>,
    /// MaxBytes specifies that this field must be the specified number of bytes
    /// at a maximum
    #[prost(uint64, optional, tag = "5")]
    pub max_bytes: ::core::option::Option<u64>,
    /// Pattern specifes that this field must match against the specified
    /// regular expression (RE2 syntax). The included expression should elide
    /// any delimiters.
    #[prost(string, optional, tag = "6")]
    pub pattern: ::core::option::Option<::prost::alloc::string::String>,
    /// Prefix specifies that this field must have the specified substring at
    /// the beginning of the string.
    #[prost(string, optional, tag = "7")]
    pub prefix: ::core::option::Option<::prost::alloc::string::String>,
    /// Suffix specifies that this field must have the specified substring at
    /// the end of the string.
    #[prost(string, optional, tag = "8")]
    pub suffix: ::core::option::Option<::prost::alloc::string::String>,
    /// Contains specifies that this field must have the specified substring
    /// anywhere in the string.
    #[prost(string, optional, tag = "9")]
    pub contains: ::core::option::Option<::prost::alloc::string::String>,
    /// NotContains specifies that this field cannot have the specified substring
    /// anywhere in the string.
    #[prost(string, optional, tag = "23")]
    pub not_contains: ::core::option::Option<::prost::alloc::string::String>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(string, repeated, tag = "10")]
    pub r#in: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(string, repeated, tag = "11")]
    pub not_in: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// This applies to regexes HTTP_HEADER_NAME and HTTP_HEADER_VALUE to enable
    /// strict header validation.
    /// By default, this is true, and HTTP header validations are RFC-compliant.
    /// Setting to false will enable a looser validations that only disallows
    /// \r\n\0 characters, which can be used to bypass header matching rules.
    #[prost(bool, optional, tag = "25", default = "true")]
    pub strict: ::core::option::Option<bool>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "26")]
    pub ignore_empty: ::core::option::Option<bool>,
    /// WellKnown rules provide advanced constraints against common string
    /// patterns
    #[prost(
        oneof = "string_rules::WellKnown",
        tags = "12, 13, 14, 15, 16, 17, 18, 21, 22, 24"
    )]
    pub well_known: ::core::option::Option<string_rules::WellKnown>,
}
/// Nested message and enum types in `StringRules`.
pub mod string_rules {
    /// WellKnown rules provide advanced constraints against common string
    /// patterns
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum WellKnown {
        /// Email specifies that the field must be a valid email address as
        /// defined by RFC 5322
        #[prost(bool, tag = "12")]
        Email(bool),
        /// Hostname specifies that the field must be a valid hostname as
        /// defined by RFC 1034. This constraint does not support
        /// internationalized domain names (IDNs).
        #[prost(bool, tag = "13")]
        Hostname(bool),
        /// Ip specifies that the field must be a valid IP (v4 or v6) address.
        /// Valid IPv6 addresses should not include surrounding square brackets.
        #[prost(bool, tag = "14")]
        Ip(bool),
        /// Ipv4 specifies that the field must be a valid IPv4 address.
        #[prost(bool, tag = "15")]
        Ipv4(bool),
        /// Ipv6 specifies that the field must be a valid IPv6 address. Valid
        /// IPv6 addresses should not include surrounding square brackets.
        #[prost(bool, tag = "16")]
        Ipv6(bool),
        /// Uri specifies that the field must be a valid, absolute URI as defined
        /// by RFC 3986
        #[prost(bool, tag = "17")]
        Uri(bool),
        /// UriRef specifies that the field must be a valid URI as defined by RFC
        /// 3986 and may be relative or absolute.
        #[prost(bool, tag = "18")]
        UriRef(bool),
        /// Address specifies that the field must be either a valid hostname as
        /// defined by RFC 1034 (which does not support internationalized domain
        /// names or IDNs), or it can be a valid IP (v4 or v6).
        #[prost(bool, tag = "21")]
        Address(bool),
        /// Uuid specifies that the field must be a valid UUID as defined by
        /// RFC 4122
        #[prost(bool, tag = "22")]
        Uuid(bool),
        /// WellKnownRegex specifies a common well known pattern defined as a regex.
        #[prost(enumeration = "super::KnownRegex", tag = "24")]
        WellKnownRegex(i32),
    }
}
/// BytesRules describe the constraints applied to `bytes` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BytesRules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(bytes = "vec", optional, tag = "1")]
    pub r#const: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Len specifies that this field must be the specified number of bytes
    #[prost(uint64, optional, tag = "13")]
    pub len: ::core::option::Option<u64>,
    /// MinLen specifies that this field must be the specified number of bytes
    /// at a minimum
    #[prost(uint64, optional, tag = "2")]
    pub min_len: ::core::option::Option<u64>,
    /// MaxLen specifies that this field must be the specified number of bytes
    /// at a maximum
    #[prost(uint64, optional, tag = "3")]
    pub max_len: ::core::option::Option<u64>,
    /// Pattern specifes that this field must match against the specified
    /// regular expression (RE2 syntax). The included expression should elide
    /// any delimiters.
    #[prost(string, optional, tag = "4")]
    pub pattern: ::core::option::Option<::prost::alloc::string::String>,
    /// Prefix specifies that this field must have the specified bytes at the
    /// beginning of the string.
    #[prost(bytes = "vec", optional, tag = "5")]
    pub prefix: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Suffix specifies that this field must have the specified bytes at the
    /// end of the string.
    #[prost(bytes = "vec", optional, tag = "6")]
    pub suffix: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Contains specifies that this field must have the specified bytes
    /// anywhere in the string.
    #[prost(bytes = "vec", optional, tag = "7")]
    pub contains: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(bytes = "vec", repeated, tag = "8")]
    pub r#in: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(bytes = "vec", repeated, tag = "9")]
    pub not_in: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "14")]
    pub ignore_empty: ::core::option::Option<bool>,
    /// WellKnown rules provide advanced constraints against common byte
    /// patterns
    #[prost(oneof = "bytes_rules::WellKnown", tags = "10, 11, 12")]
    pub well_known: ::core::option::Option<bytes_rules::WellKnown>,
}
/// Nested message and enum types in `BytesRules`.
pub mod bytes_rules {
    /// WellKnown rules provide advanced constraints against common byte
    /// patterns
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum WellKnown {
        /// Ip specifies that the field must be a valid IP (v4 or v6) address in
        /// byte format
        #[prost(bool, tag = "10")]
        Ip(bool),
        /// Ipv4 specifies that the field must be a valid IPv4 address in byte
        /// format
        #[prost(bool, tag = "11")]
        Ipv4(bool),
        /// Ipv6 specifies that the field must be a valid IPv6 address in byte
        /// format
        #[prost(bool, tag = "12")]
        Ipv6(bool),
    }
}
/// EnumRules describe the constraints applied to enum values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnumRules {
    /// Const specifies that this field must be exactly the specified value
    #[prost(int32, optional, tag = "1")]
    pub r#const: ::core::option::Option<i32>,
    /// DefinedOnly specifies that this field must be only one of the defined
    /// values for this enum, failing on any undefined value.
    #[prost(bool, optional, tag = "2")]
    pub defined_only: ::core::option::Option<bool>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(int32, repeated, packed = "false", tag = "3")]
    pub r#in: ::prost::alloc::vec::Vec<i32>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(int32, repeated, packed = "false", tag = "4")]
    pub not_in: ::prost::alloc::vec::Vec<i32>,
}
/// MessageRules describe the constraints applied to embedded message values.
/// For message-type fields, validation is performed recursively.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageRules {
    /// Skip specifies that the validation rules of this field should not be
    /// evaluated
    #[prost(bool, optional, tag = "1")]
    pub skip: ::core::option::Option<bool>,
    /// Required specifies that this field must be set
    #[prost(bool, optional, tag = "2")]
    pub required: ::core::option::Option<bool>,
}
/// RepeatedRules describe the constraints applied to `repeated` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RepeatedRules {
    /// MinItems specifies that this field must have the specified number of
    /// items at a minimum
    #[prost(uint64, optional, tag = "1")]
    pub min_items: ::core::option::Option<u64>,
    /// MaxItems specifies that this field must have the specified number of
    /// items at a maximum
    #[prost(uint64, optional, tag = "2")]
    pub max_items: ::core::option::Option<u64>,
    /// Unique specifies that all elements in this field must be unique. This
    /// contraint is only applicable to scalar and enum types (messages are not
    /// supported).
    #[prost(bool, optional, tag = "3")]
    pub unique: ::core::option::Option<bool>,
    /// Items specifies the contraints to be applied to each item in the field.
    /// Repeated message fields will still execute validation against each item
    /// unless skip is specified here.
    #[prost(message, optional, boxed, tag = "4")]
    pub items: ::core::option::Option<::prost::alloc::boxed::Box<FieldRules>>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "5")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// MapRules describe the constraints applied to `map` values
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MapRules {
    /// MinPairs specifies that this field must have the specified number of
    /// KVs at a minimum
    #[prost(uint64, optional, tag = "1")]
    pub min_pairs: ::core::option::Option<u64>,
    /// MaxPairs specifies that this field must have the specified number of
    /// KVs at a maximum
    #[prost(uint64, optional, tag = "2")]
    pub max_pairs: ::core::option::Option<u64>,
    /// NoSparse specifies values in this field cannot be unset. This only
    /// applies to map's with message value types.
    #[prost(bool, optional, tag = "3")]
    pub no_sparse: ::core::option::Option<bool>,
    /// Keys specifies the constraints to be applied to each key in the field.
    #[prost(message, optional, boxed, tag = "4")]
    pub keys: ::core::option::Option<::prost::alloc::boxed::Box<FieldRules>>,
    /// Values specifies the constraints to be applied to the value of each key
    /// in the field. Message values will still have their validations evaluated
    /// unless skip is specified here.
    #[prost(message, optional, boxed, tag = "5")]
    pub values: ::core::option::Option<::prost::alloc::boxed::Box<FieldRules>>,
    /// IgnoreEmpty specifies that the validation rules of this field should be
    /// evaluated only if the field is not empty
    #[prost(bool, optional, tag = "6")]
    pub ignore_empty: ::core::option::Option<bool>,
}
/// AnyRules describe constraints applied exclusively to the
/// `google.protobuf.Any` well-known type
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AnyRules {
    /// Required specifies that this field must be set
    #[prost(bool, optional, tag = "1")]
    pub required: ::core::option::Option<bool>,
    /// In specifies that this field's `type_url` must be equal to one of the
    /// specified values.
    #[prost(string, repeated, tag = "2")]
    pub r#in: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// NotIn specifies that this field's `type_url` must not be equal to any of
    /// the specified values.
    #[prost(string, repeated, tag = "3")]
    pub not_in: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// DurationRules describe the constraints applied exclusively to the
/// `google.protobuf.Duration` well-known type
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DurationRules {
    /// Required specifies that this field must be set
    #[prost(bool, optional, tag = "1")]
    pub required: ::core::option::Option<bool>,
    /// Const specifies that this field must be exactly the specified value
    #[prost(message, optional, tag = "2")]
    pub r#const: ::core::option::Option<::prost_types::Duration>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(message, optional, tag = "3")]
    pub lt: ::core::option::Option<::prost_types::Duration>,
    /// Lt specifies that this field must be less than the specified value,
    /// inclusive
    #[prost(message, optional, tag = "4")]
    pub lte: ::core::option::Option<::prost_types::Duration>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive
    #[prost(message, optional, tag = "5")]
    pub gt: ::core::option::Option<::prost_types::Duration>,
    /// Gte specifies that this field must be greater than the specified value,
    /// inclusive
    #[prost(message, optional, tag = "6")]
    pub gte: ::core::option::Option<::prost_types::Duration>,
    /// In specifies that this field must be equal to one of the specified
    /// values
    #[prost(message, repeated, tag = "7")]
    pub r#in: ::prost::alloc::vec::Vec<::prost_types::Duration>,
    /// NotIn specifies that this field cannot be equal to one of the specified
    /// values
    #[prost(message, repeated, tag = "8")]
    pub not_in: ::prost::alloc::vec::Vec<::prost_types::Duration>,
}
/// TimestampRules describe the constraints applied exclusively to the
/// `google.protobuf.Timestamp` well-known type
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TimestampRules {
    /// Required specifies that this field must be set
    #[prost(bool, optional, tag = "1")]
    pub required: ::core::option::Option<bool>,
    /// Const specifies that this field must be exactly the specified value
    #[prost(message, optional, tag = "2")]
    pub r#const: ::core::option::Option<::prost_types::Timestamp>,
    /// Lt specifies that this field must be less than the specified value,
    /// exclusive
    #[prost(message, optional, tag = "3")]
    pub lt: ::core::option::Option<::prost_types::Timestamp>,
    /// Lte specifies that this field must be less than the specified value,
    /// inclusive
    #[prost(message, optional, tag = "4")]
    pub lte: ::core::option::Option<::prost_types::Timestamp>,
    /// Gt specifies that this field must be greater than the specified value,
    /// exclusive
    #[prost(message, optional, tag = "5")]
    pub gt: ::core::option::Option<::prost_types::Timestamp>,
    /// Gte specifies that this field must be greater than the specified value,
    /// inclusive
    #[prost(message, optional, tag = "6")]
    pub gte: ::core::option::Option<::prost_types::Timestamp>,
    /// LtNow specifies that this must be less than the current time. LtNow
    /// can only be used with the Within rule.
    #[prost(bool, optional, tag = "7")]
    pub lt_now: ::core::option::Option<bool>,
    /// GtNow specifies that this must be greater than the current time. GtNow
    /// can only be used with the Within rule.
    #[prost(bool, optional, tag = "8")]
    pub gt_now: ::core::option::Option<bool>,
    /// Within specifies that this field must be within this duration of the
    /// current time. This constraint can be used alone or with the LtNow and
    /// GtNow rules.
    #[prost(message, optional, tag = "9")]
    pub within: ::core::option::Option<::prost_types::Duration>,
}
/// WellKnownRegex contain some well-known patterns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum KnownRegex {
    Unknown = 0,
    /// HTTP header name as defined by RFC 7230.
    HttpHeaderName = 1,
    /// HTTP header value as defined by RFC 7230.
    HttpHeaderValue = 2,
}
impl KnownRegex {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            KnownRegex::Unknown => "UNKNOWN",
            KnownRegex::HttpHeaderName => "HTTP_HEADER_NAME",
            KnownRegex::HttpHeaderValue => "HTTP_HEADER_VALUE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UNKNOWN" => Some(Self::Unknown),
            "HTTP_HEADER_NAME" => Some(Self::HttpHeaderName),
            "HTTP_HEADER_VALUE" => Some(Self::HttpHeaderValue),
            _ => None,
        }
    }
}
