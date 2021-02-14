/// Protobuf config for this filter.
pub(super) mod quilkin {
    pub mod extensions {
        pub mod filters {
            pub mod local_rate_limit {
                pub mod v1alpha1 {
                    #![doc(hidden)]
                    tonic::include_proto!("quilkin.extensions.filters.local_rate_limit.v1alpha1");
                }
            }
        }
    }
}
