/*
 * Copyright 2020 Google LLC All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

mod udpa {
    pub mod core {
        pub mod v1 {
            #![cfg(not(doctest))]
            #![doc(hidden)]
            tonic::include_proto!("udpa.core.v1");
        }
    }
}

mod envoy {
    pub mod r#type {
        pub mod matcher {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.r#type.matcher.v3");
            }
        }
        pub mod metadata {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.r#type.metadata.v3");
            }
        }
        pub mod tracing {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.r#type.tracing.v3");
            }
        }
        pub mod v3 {
            #![cfg(not(doctest))]
            #![doc(hidden)]
            tonic::include_proto!("envoy.r#type.v3");
        }
    }
    pub mod config {
        pub mod accesslog {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.accesslog.v3");
            }
        }
        pub mod cluster {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.cluster.v3");
            }
        }
        pub mod core {
            pub mod v3 {
                #![allow(clippy::large_enum_variant)]
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.core.v3");
            }
        }
        pub mod endpoint {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.endpoint.v3");
            }
        }
        pub mod listener {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.listener.v3");
            }
        }
        pub mod route {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.config.route.v3");
            }
        }
    }
    pub mod service {
        pub mod discovery {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.service.discovery.v3");
            }
        }
        pub mod cluster {
            pub mod v3 {
                #![cfg(not(doctest))]
                #![doc(hidden)]
                tonic::include_proto!("envoy.service.cluster.v3");
            }
        }
    }
}

mod google {
    pub mod rpc {
        #![cfg(not(doctest))]
        #![doc(hidden)]
        tonic::include_proto!("google.rpc");
    }
}

const ENDPOINT_TYPE: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
const CLUSTER_TYPE: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const LISTENER_TYPE: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";

#[cfg(not(doctest))]
pub(crate) mod ads_client;
#[cfg(not(doctest))]
mod cluster;
mod error;
#[cfg(not(doctest))]
mod listener;
#[cfg(not(doctest))]
mod metadata;
