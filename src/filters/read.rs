/*
 * Copyright 2021 Google LLC
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

use std::sync::Arc;

#[cfg(doc)]
use crate::filters::Filter;
use crate::{
    cluster::ClusterMap,
    net::endpoint::{metadata::DynamicMetadata, Endpoint, EndpointAddress},
};

/// The input arguments to [`Filter::read`].
#[non_exhaustive]
pub struct ReadContext {
    /// The upstream endpoints that the packet will be forwarded to.
    pub clusters: Arc<ClusterMap>,
    /// The upstream endpoints that the packet will be forwarded to.
    pub destinations: Vec<Endpoint>,
    /// The source of the received packet.
    pub source: EndpointAddress,
    /// Contents of the received packet.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another.
    pub metadata: DynamicMetadata,
}

impl ReadContext {
    /// Creates a new [`ReadContext`].
    pub fn new(clusters: Arc<ClusterMap>, source: EndpointAddress, contents: Vec<u8>) -> Self {
        Self {
            clusters,
            destinations: Vec::new(),
            source,
            contents,
            metadata: DynamicMetadata::new(),
        }
    }

    pub fn metadata(mut self, metadata: DynamicMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}
