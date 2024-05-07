#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FileStatusAnnotation {
    #[prost(bool, tag = "1")]
    pub work_in_progress: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MessageStatusAnnotation {
    #[prost(bool, tag = "1")]
    pub work_in_progress: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FieldStatusAnnotation {
    #[prost(bool, tag = "1")]
    pub work_in_progress: bool,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StatusAnnotation {
    #[prost(bool, tag = "1")]
    pub work_in_progress: bool,
    #[prost(enumeration = "PackageVersionStatus", tag = "2")]
    pub package_version_status: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum PackageVersionStatus {
    Unknown = 0,
    Frozen = 1,
    Active = 2,
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
            PackageVersionStatus::NextMajorVersionCandidate => "NEXT_MAJOR_VERSION_CANDIDATE",
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
