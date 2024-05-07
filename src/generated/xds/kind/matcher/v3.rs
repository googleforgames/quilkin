#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegexMatcher {
    #[prost(string, tag = "2")]
    pub regex: ::prost::alloc::string::String,
    #[prost(oneof = "regex_matcher::EngineType", tags = "1")]
    pub engine_type: ::core::option::Option<regex_matcher::EngineType>,
}
/// Nested message and enum types in `RegexMatcher`.
pub mod regex_matcher {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GoogleRe2 {}
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum EngineType {
        #[prost(message, tag = "1")]
        GoogleRe2(GoogleRe2),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringMatcher {
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
        #[prost(string, tag = "1")]
        Exact(::prost::alloc::string::String),
        #[prost(string, tag = "2")]
        Prefix(::prost::alloc::string::String),
        #[prost(string, tag = "3")]
        Suffix(::prost::alloc::string::String),
        #[prost(message, tag = "5")]
        SafeRegex(super::RegexMatcher),
        #[prost(string, tag = "7")]
        Contains(::prost::alloc::string::String),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListStringMatcher {
    #[prost(message, repeated, tag = "1")]
    pub patterns: ::prost::alloc::vec::Vec<StringMatcher>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Matcher {
    #[prost(message, optional, boxed, tag = "3")]
    pub on_no_match: ::core::option::Option<::prost::alloc::boxed::Box<matcher::OnMatch>>,
    #[prost(oneof = "matcher::MatcherType", tags = "1, 2")]
    pub matcher_type: ::core::option::Option<matcher::MatcherType>,
}
/// Nested message and enum types in `Matcher`.
pub mod matcher {
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
            #[prost(message, tag = "1")]
            Matcher(::prost::alloc::boxed::Box<super::super::Matcher>),
            #[prost(message, tag = "2")]
            Action(super::super::super::super::super::core::v3::TypedExtensionConfig),
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MatcherList {
        #[prost(message, repeated, tag = "1")]
        pub matchers: ::prost::alloc::vec::Vec<matcher_list::FieldMatcher>,
    }
    /// Nested message and enum types in `MatcherList`.
    pub mod matcher_list {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Predicate {
            #[prost(oneof = "predicate::MatchType", tags = "1, 2, 3, 4")]
            pub match_type: ::core::option::Option<predicate::MatchType>,
        }
        /// Nested message and enum types in `Predicate`.
        pub mod predicate {
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct SinglePredicate {
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
                    #[prost(message, tag = "2")]
                    ValueMatch(super::super::super::super::StringMatcher),
                    #[prost(message, tag = "3")]
                    CustomMatch(
                        super::super::super::super::super::super::super::core::v3::TypedExtensionConfig,
                    ),
                }
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Message)]
            pub struct PredicateList {
                #[prost(message, repeated, tag = "1")]
                pub predicate: ::prost::alloc::vec::Vec<super::Predicate>,
            }
            #[allow(clippy::derive_partial_eq_without_eq)]
            #[derive(Clone, PartialEq, ::prost::Oneof)]
            pub enum MatchType {
                #[prost(message, tag = "1")]
                SinglePredicate(SinglePredicate),
                #[prost(message, tag = "2")]
                OrMatcher(PredicateList),
                #[prost(message, tag = "3")]
                AndMatcher(PredicateList),
                #[prost(message, tag = "4")]
                NotMatcher(::prost::alloc::boxed::Box<super::Predicate>),
            }
        }
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct FieldMatcher {
            #[prost(message, optional, tag = "1")]
            pub predicate: ::core::option::Option<Predicate>,
            #[prost(message, optional, tag = "2")]
            pub on_match: ::core::option::Option<super::OnMatch>,
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MatcherTree {
        #[prost(message, optional, tag = "1")]
        pub input:
            ::core::option::Option<super::super::super::super::core::v3::TypedExtensionConfig>,
        #[prost(oneof = "matcher_tree::TreeType", tags = "2, 3, 4")]
        pub tree_type: ::core::option::Option<matcher_tree::TreeType>,
    }
    /// Nested message and enum types in `MatcherTree`.
    pub mod matcher_tree {
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MatchMap {
            #[prost(map = "string, message", tag = "1")]
            pub map: ::std::collections::HashMap<::prost::alloc::string::String, super::OnMatch>,
        }
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum TreeType {
            #[prost(message, tag = "2")]
            ExactMatchMap(MatchMap),
            #[prost(message, tag = "3")]
            PrefixMatchMap(MatchMap),
            #[prost(message, tag = "4")]
            CustomMatch(super::super::super::super::super::core::v3::TypedExtensionConfig),
        }
    }
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum MatcherType {
        #[prost(message, tag = "1")]
        MatcherList(MatcherList),
        #[prost(message, tag = "2")]
        MatcherTree(MatcherTree),
    }
}
