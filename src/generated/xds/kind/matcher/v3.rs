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
    pub struct GoogleRe2 {}
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum EngineType {
        /// Google's RE2 regex engine.
        #[prost(message, tag = "1")]
        GoogleRe2(GoogleRe2),
    }
}
/// Specifies the way to match a string.
/// \[#next-free-field: 8\]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringMatcher {
    /// If true, indicates the exact/prefix/suffix matching should be case
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
/// A matcher, which may traverse a matching tree in order to result in a match
/// action. During matching, the tree will be traversed until a match is found,
/// or if no match is found the action specified by the most specific on_no_match
/// will be evaluated. As an on_no_match might result in another matching tree
/// being evaluated, this process might repeat several times until the final
/// OnMatch (or no match) is decided.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Matcher {
    /// Optional OnMatch to use if no matcher above matched (e.g., if there are no
    /// matchers specified above, or if none of the matches specified above
    /// succeeded). If no matcher above matched and this field is not populated,
    /// the match will be considered unsuccessful.
    #[prost(message, optional, boxed, tag = "3")]
    pub on_no_match: ::core::option::Option<::prost::alloc::boxed::Box<matcher::OnMatch>>,
    #[prost(oneof = "matcher::MatcherType", tags = "1, 2")]
    pub matcher_type: ::core::option::Option<matcher::MatcherType>,
}
/// Nested message and enum types in `Matcher`.
pub mod matcher {
    /// What to do if a match is successful.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct OnMatch {
        #[prost(oneof = "on_match::OnMatch", tags = "1, 2")]
        pub on_match: ::core::option::Option<on_match::OnMatch>,
    }
    /// Nested message and enum types in `OnMatch`.
    pub mod on_match {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum OnMatch {
            /// Nested matcher to evaluate.
            /// If the nested matcher does not match and does not specify
            /// on_no_match, then this matcher is considered not to have
            /// matched, even if a predicate at this level or above returned
            /// true.
            #[prost(message, tag = "1")]
            Matcher(::prost::alloc::boxed::Box<super::super::Matcher>),
            /// Protocol-specific action to take.
            #[prost(message, tag = "2")]
            Action(super::super::super::super::super::core::v3::TypedExtensionConfig),
        }
    }
    /// A linear list of field matchers.
    /// The field matchers are evaluated in order, and the first match
    /// wins.
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MatcherList {
        /// A list of matchers. First match wins.
        #[prost(message, repeated, tag = "1")]
        pub matchers: ::prost::alloc::vec::Vec<matcher_list::FieldMatcher>,
    }
    /// Nested message and enum types in `MatcherList`.
    pub mod matcher_list {
        /// Predicate to determine if a match is successful.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Predicate {
            #[prost(oneof = "predicate::MatchType", tags = "1, 2, 3, 4")]
            pub match_type: ::core::option::Option<predicate::MatchType>,
        }
        /// Nested message and enum types in `Predicate`.
        pub mod predicate {
            /// Predicate for a single input field.
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct SinglePredicate {
                /// Protocol-specific specification of input field to match on.
                /// \[#extension-category: envoy.matching.common_inputs\]
                #[prost(message, optional, tag = "1")]
                pub input: ::core::option::Option<
                    super::super::super::super::super::super::core::v3::TypedExtensionConfig,
                >,
                #[prost(oneof = "single_predicate::Matcher", tags = "2, 3")]
                pub matcher: ::core::option::Option<single_predicate::Matcher>,
            }
            /// Nested message and enum types in `SinglePredicate`.
            pub mod single_predicate {
                #[allow(clippy::derive_partial_eq_without_eq)]
                #[derive(Clone, PartialEq, ::prost::Oneof)]
                pub enum Matcher {
                    /// Built-in string matcher.
                    #[prost(message, tag = "2")]
                    ValueMatch(super::super::super::super::StringMatcher),
                    /// Extension for custom matching logic.
                    /// \[#extension-category: envoy.matching.input_matchers\]
                    #[prost(message, tag = "3")]
                    CustomMatch(
                        super::super::super::super::super::super::super::core::v3::TypedExtensionConfig,
                    ),
                }
            }
            /// A list of two or more matchers. Used to allow using a list within a
            /// oneof.
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct PredicateList {
                #[prost(message, repeated, tag = "1")]
                pub predicate: ::prost::alloc::vec::Vec<super::Predicate>,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum MatchType {
                /// A single predicate to evaluate.
                #[prost(message, tag = "1")]
                SinglePredicate(SinglePredicate),
                /// A list of predicates to be OR-ed together.
                #[prost(message, tag = "2")]
                OrMatcher(PredicateList),
                /// A list of predicates to be AND-ed together.
                #[prost(message, tag = "3")]
                AndMatcher(PredicateList),
                /// The invert of a predicate
                #[prost(message, tag = "4")]
                NotMatcher(::prost::alloc::boxed::Box<super::Predicate>),
            }
        }
        /// An individual matcher.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct FieldMatcher {
            /// Determines if the match succeeds.
            #[prost(message, optional, tag = "1")]
            pub predicate: ::core::option::Option<Predicate>,
            /// What to do if the match succeeds.
            #[prost(message, optional, tag = "2")]
            pub on_match: ::core::option::Option<super::OnMatch>,
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MatcherTree {
        /// Protocol-specific specification of input field to match on.
        #[prost(message, optional, tag = "1")]
        pub input:
            ::core::option::Option<super::super::super::super::core::v3::TypedExtensionConfig>,
        /// Exact or prefix match maps in which to look up the input value.
        /// If the lookup succeeds, the match is considered successful, and
        /// the corresponding OnMatch is used.
        #[prost(oneof = "matcher_tree::TreeType", tags = "2, 3, 4")]
        pub tree_type: ::core::option::Option<matcher_tree::TreeType>,
    }
    /// Nested message and enum types in `MatcherTree`.
    pub mod matcher_tree {
        /// A map of configured matchers. Used to allow using a map within a oneof.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MatchMap {
            #[prost(map = "string, message", tag = "1")]
            pub map: ::std::collections::HashMap<::prost::alloc::string::String, super::OnMatch>,
        }
        /// Exact or prefix match maps in which to look up the input value.
        /// If the lookup succeeds, the match is considered successful, and
        /// the corresponding OnMatch is used.
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum TreeType {
            #[prost(message, tag = "2")]
            ExactMatchMap(MatchMap),
            /// Longest matching prefix wins.
            #[prost(message, tag = "3")]
            PrefixMatchMap(MatchMap),
            /// Extension for custom matching logic.
            #[prost(message, tag = "4")]
            CustomMatch(super::super::super::super::super::core::v3::TypedExtensionConfig),
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum MatcherType {
        /// A linear list of matchers to evaluate.
        #[prost(message, tag = "1")]
        MatcherList(MatcherList),
        /// A match tree to evaluate.
        #[prost(message, tag = "2")]
        MatcherTree(MatcherTree),
    }
}
