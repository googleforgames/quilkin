#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatusAnnotation {
    /// The entity is work-in-progress and subject to breaking changes.
    #[prost(bool, tag = "1")]
    pub work_in_progress: bool,
    /// The entity belongs to a package with the given version status.
    #[prost(enumeration = "PackageVersionStatus", tag = "2")]
    pub package_version_status: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PackageVersionStatus {
    /// Unknown package version status.
    Unknown = 0,
    /// This version of the package is frozen.
    Frozen = 1,
    /// This version of the package is the active development version.
    Active = 2,
    /// This version of the package is the candidate for the next major version. It
    /// is typically machine generated from the active development version.
    NextMajorVersionCandidate = 3,
}
impl PackageVersionStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            PackageVersionStatus::Unknown => "UNKNOWN",
            PackageVersionStatus::Frozen => "FROZEN",
            PackageVersionStatus::Active => "ACTIVE",
            PackageVersionStatus::NextMajorVersionCandidate => {
                "NEXT_MAJOR_VERSION_CANDIDATE"
            }
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "UNKNOWN" => Some(Self::Unknown),
            "FROZEN" => Some(Self::Frozen),
            "ACTIVE" => Some(Self::Active),
            "NEXT_MAJOR_VERSION_CANDIDATE" => Some(Self::NextMajorVersionCandidate),
            _ => None,
        }
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VersioningAnnotation {
    /// Track the previous message type. E.g. this message might be
    /// udpa.foo.v3alpha.Foo and it was previously udpa.bar.v2.Bar. This
    /// information is consumed by UDPA via proto descriptors.
    #[prost(string, tag = "1")]
    pub previous_message_type: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MigrateAnnotation {
    /// Rename the message/enum/enum value in next version.
    #[prost(string, tag = "1")]
    pub rename: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FieldMigrateAnnotation {
    /// Rename the field in next version.
    #[prost(string, tag = "1")]
    pub rename: ::prost::alloc::string::String,
    /// Add the field to a named oneof in next version. If this already exists, the
    /// field will join its siblings under the oneof, otherwise a new oneof will be
    /// created with the given name.
    #[prost(string, tag = "2")]
    pub oneof_promotion: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileMigrateAnnotation {
    /// Move all types in the file to another package, this implies changing proto
    /// file path.
    #[prost(string, tag = "2")]
    pub move_to_package: ::prost::alloc::string::String,
}
/// These annotations indicate metadata for the purpose of understanding the
/// security significance of fields.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FieldSecurityAnnotation {
    /// Field should be set in the presence of untrusted downstreams.
    #[prost(bool, tag = "1")]
    pub configure_for_untrusted_downstream: bool,
    /// Field should be set in the presence of untrusted upstreams.
    #[prost(bool, tag = "2")]
    pub configure_for_untrusted_upstream: bool,
}
