/*
 * Copyright 2020 Google LLC
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

pub mod client;
pub mod config;
pub mod locality;
pub mod metrics;
pub mod net;
pub mod server;

pub use client::{AdsClient, Client};

pub use generated::envoy::{
    config::core::v3::{self as core, socket_address},
    config::listener::v3 as listener,
    service::discovery::v3 as discovery,
};
pub use generated::quilkin::config::v1alpha1 as proto;
pub use quilkin_proto::generated;

pub type Result<T, E = eyre::Error> = std::result::Result<T, E>;
