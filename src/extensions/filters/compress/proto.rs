/// Protobuf config for this filter.
pub(super) mod quilkin {
    pub mod extensions {
        pub mod filters {
            pub mod compress {
                pub mod v1alpha1 {
                    #![doc(hidden)]
                    tonic::include_proto!("quilkin.extensions.filters.compress.v1alpha1");
                }
            }
        }
    }
}
