/// Protobuf config for this filter.
pub(super) mod quilkin {
    pub mod extensions {
        pub mod filters {
            pub mod load_balancer {
                pub mod v1alpha1 {
                    #![doc(hidden)]
                    tonic::include_proto!("quilkin.extensions.filters.load_balancer.v1alpha1");
                }
            }
        }
    }
}
