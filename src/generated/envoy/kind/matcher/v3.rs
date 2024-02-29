/// Specifies the way to match a double value.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DoubleMatcher {
    #[prost(oneof = "double_matcher::MatchPattern", tags = "1, 2")]
    pub match_pattern: ::core::option::Option<double_matcher::MatchPattern>,
}
/// Nested message and enum types in `DoubleMatcher`.
pub mod double_matcher {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum MatchPattern {
        /// If specified, the input double value must be in the range specified here.
        /// Note: The range is using half-open interval semantics [start, end).
        #[prost(message, tag = "1")]
        Range(super::super::super::v3::DoubleRange),
        /// If specified, the input double value must be equal to the value specified
        /// here.
        #[prost(double, tag = "2")]
        Exact(f64),
    }
}
/// A regex matcher designed for safety when used with untrusted input.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegexMatcher {
    /// The regex match string. The string must be supported by the configured
    /// engine.
    #[prost(string, tag = "2")]
    pub regex: ::prost::alloc::string::String,
    #[prost(oneof = "regex_matcher::EngineType", tags = "1")]
    pub engine_type: ::core::option::Option<regex_matcher::EngineType>,
}
/// Nested message and enum types in `RegexMatcher`.
pub mod regex_matcher {
    /// Google's `RE2 <<https://github.com/google/re2>`_> regex engine. The regex
    /// string must adhere to the documented `syntax
    /// <<https://github.com/google/re2/wiki/Syntax>`_.> The engine is designed to
    /// complete execution in linear time as well as limit the amount of memory
    /// used.
    ///
    /// Envoy supports program size checking via runtime. The runtime keys
    /// `re2.max_program_size.error_level` and `re2.max_program_size.warn_level`
    /// can be set to integers as the maximum program size or complexity that a
    /// compiled regex can have before an exception is thrown or a warning is
    /// logged, respectively. `re2.max_program_size.error_level` defaults to 100,
    /// and `re2.max_program_size.warn_level` has no default if unset (will not
    /// check/log a warning).
    ///
    /// Envoy emits two stats for tracking the program size of regexes: the
    /// histogram `re2.program_size`, which records the program size, and the
    /// counter `re2.exceeded_warn_level`, which is incremented each time the
    /// program size exceeds the warn level threshold.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GoogleRe2 {
        /// This field controls the RE2 "program size" which is a rough estimate of
        /// how complex a compiled regex is to evaluate. A regex that has a program
        /// size greater than the configured value will fail to compile. In this
        /// case, the configured max program size can be increased or the regex can
        /// be simplified. If not specified, the default is 100.
        ///
        /// This field is deprecated; regexp validation should be performed on the
        /// management server instead of being done by each individual client.
        ///
        /// .. note::
        ///
        ///   Although this field is deprecated, the program size will still be
        ///   checked against the global ``re2.max_program_size.error_level`` runtime
        ///   value.
        ///
        #[deprecated]
        #[prost(message, optional, tag = "1")]
        pub max_program_size: ::core::option::Option<u32>,
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum EngineType {
        /// Google's RE2 regex engine.
        #[prost(message, tag = "1")]
        GoogleRe2(GoogleRe2),
    }
}
/// Describes how to match a string and then produce a new string using a regular
/// expression and a substitution string.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegexMatchAndSubstitute {
    /// The regular expression used to find portions of a string (hereafter called
    /// the "subject string") that should be replaced. When a new string is
    /// produced during the substitution operation, the new string is initially
    /// the same as the subject string, but then all matches in the subject string
    /// are replaced by the substitution string. If replacing all matches isn't
    /// desired, regular expression anchors can be used to ensure a single match,
    /// so as to replace just one occurrence of a pattern. Capture groups can be
    /// used in the pattern to extract portions of the subject string, and then
    /// referenced in the substitution string.
    #[prost(message, optional, tag = "1")]
    pub pattern: ::core::option::Option<RegexMatcher>,
    /// The string that should be substituted into matching portions of the
    /// subject string during a substitution operation to produce a new string.
    /// Capture groups in the pattern can be referenced in the substitution
    /// string. Note, however, that the syntax for referring to capture groups is
    /// defined by the chosen regular expression engine. Google's `RE2
    /// <<https://github.com/google/re2>`_> regular expression engine uses a
    /// backslash followed by the capture group number to denote a numbered
    /// capture group. E.g., ``\1`` refers to capture group 1, and ``\2`` refers
    /// to capture group 2.
    #[prost(string, tag = "2")]
    pub substitution: ::prost::alloc::string::String,
}
/// Specifies the way to match a string.
/// \[#next-free-field: 8\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringMatcher {
    /// If true, indicates the exact/prefix/suffix/contains matching should be case
    /// insensitive. This has no effect for the safe_regex match. For example, the
    /// matcher *data* will match both input string *Data* and *data* if set to
    /// true.
    #[prost(bool, tag = "6")]
    pub ignore_case: bool,
    #[prost(oneof = "string_matcher::MatchPattern", tags = "1, 2, 3, 5, 7")]
    pub match_pattern: ::core::option::Option<string_matcher::MatchPattern>,
}
/// Nested message and enum types in `StringMatcher`.
pub mod string_matcher {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum MatchPattern {
        /// The input string must match exactly the string specified here.
        ///
        /// Examples:
        ///
        /// * *abc* only matches the value *abc*.
        #[prost(string, tag = "1")]
        Exact(::prost::alloc::string::String),
        /// The input string must have the prefix specified here.
        /// Note: empty prefix is not allowed, please use regex instead.
        ///
        /// Examples:
        ///
        /// * *abc* matches the value *abc.xyz*
        #[prost(string, tag = "2")]
        Prefix(::prost::alloc::string::String),
        /// The input string must have the suffix specified here.
        /// Note: empty prefix is not allowed, please use regex instead.
        ///
        /// Examples:
        ///
        /// * *abc* matches the value *xyz.abc*
        #[prost(string, tag = "3")]
        Suffix(::prost::alloc::string::String),
        /// The input string must match the regular expression specified here.
        #[prost(message, tag = "5")]
        SafeRegex(super::RegexMatcher),
        /// The input string must have the substring specified here.
        /// Note: empty contains match is not allowed, please use regex instead.
        ///
        /// Examples:
        ///
        /// * *abc* matches the value *xyz.abc.def*
        #[prost(string, tag = "7")]
        Contains(::prost::alloc::string::String),
    }
}
/// Specifies a list of ways to match a string.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListStringMatcher {
    #[prost(message, repeated, tag = "1")]
    pub patterns: ::prost::alloc::vec::Vec<StringMatcher>,
}
/// Specifies the way to match a ProtobufWkt::Value. Primitive values and
/// ListValue are supported. StructValue is not supported and is always not
/// matched.
/// \[#next-free-field: 7\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ValueMatcher {
    /// Specifies how to match a value.
    #[prost(oneof = "value_matcher::MatchPattern", tags = "1, 2, 3, 4, 5, 6")]
    pub match_pattern: ::core::option::Option<value_matcher::MatchPattern>,
}
/// Nested message and enum types in `ValueMatcher`.
pub mod value_matcher {
    /// NullMatch is an empty message to specify a null value.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NullMatch {}
    /// Specifies how to match a value.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum MatchPattern {
        /// If specified, a match occurs if and only if the target value is a
        /// NullValue.
        #[prost(message, tag = "1")]
        NullMatch(NullMatch),
        /// If specified, a match occurs if and only if the target value is a double
        /// value and is matched to this field.
        #[prost(message, tag = "2")]
        DoubleMatch(super::DoubleMatcher),
        /// If specified, a match occurs if and only if the target value is a string
        /// value and is matched to this field.
        #[prost(message, tag = "3")]
        StringMatch(super::StringMatcher),
        /// If specified, a match occurs if and only if the target value is a bool
        /// value and is equal to this field.
        #[prost(bool, tag = "4")]
        BoolMatch(bool),
        /// If specified, value match will be performed based on whether the path is
        /// referring to a valid primitive value in the metadata. If the path is
        /// referring to a non-primitive value, the result is always not matched.
        #[prost(bool, tag = "5")]
        PresentMatch(bool),
        /// If specified, a match occurs if and only if the target value is a list
        /// value and is matched to this field.
        #[prost(message, tag = "6")]
        ListMatch(::prost::alloc::boxed::Box<super::ListMatcher>),
    }
}
/// Specifies the way to match a list value.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListMatcher {
    #[prost(oneof = "list_matcher::MatchPattern", tags = "1")]
    pub match_pattern: ::core::option::Option<list_matcher::MatchPattern>,
}
/// Nested message and enum types in `ListMatcher`.
pub mod list_matcher {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum MatchPattern {
        /// If specified, at least one of the values in the list must match the value
        /// specified.
        #[prost(message, tag = "1")]
        OneOf(::prost::alloc::boxed::Box<super::ValueMatcher>),
    }
}
/// \[#next-major-version: MetadataMatcher should use StructMatcher\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetadataMatcher {
    /// The filter name to retrieve the Struct from the Metadata.
    #[prost(string, tag = "1")]
    pub filter: ::prost::alloc::string::String,
    /// The path to retrieve the Value from the Struct.
    #[prost(message, repeated, tag = "2")]
    pub path: ::prost::alloc::vec::Vec<metadata_matcher::PathSegment>,
    /// The MetadataMatcher is matched if the value retrieved by path is matched to
    /// this value.
    #[prost(message, optional, tag = "3")]
    pub value: ::core::option::Option<ValueMatcher>,
    /// If true, the match result will be inverted.
    #[prost(bool, tag = "4")]
    pub invert: bool,
}
/// Nested message and enum types in `MetadataMatcher`.
pub mod metadata_matcher {
    /// Specifies the segment in a path to retrieve value from Metadata.
    /// Note: Currently it's not supported to retrieve a value from a list in
    /// Metadata. This means that if the segment key refers to a list, it has to be
    /// the last segment in a path.
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
