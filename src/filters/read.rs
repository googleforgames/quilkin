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
    net::{
        endpoint::{metadata::DynamicMetadata, EndpointAddress},
        ClusterMap,
    },
    pool::PoolBuffer,
};

/// The input arguments to [`Filter::read`].
pub struct ReadContext<'ctx> {
    /// The upstream endpoints that the packet will be forwarded to.
    pub endpoints: Arc<ClusterMap>,
    /// The upstream endpoints that the packet will be forwarded to.
    pub destinations: &'ctx mut Vec<EndpointAddress>,
    /// The source of the received packet.
    pub source: EndpointAddress,
    /// Contents of the received packet.
    pub contents: PoolBuffer,
    /// Arbitrary values that can be passed from one filter to another.
    pub metadata: DynamicMetadata,
}

impl<'ctx> ReadContext<'ctx> {
    /// Creates a new [`ReadContext`].
    #[inline]
    pub fn new(
        endpoints: Arc<ClusterMap>,
        source: EndpointAddress,
        contents: PoolBuffer,
        destinations: &'ctx mut Vec<EndpointAddress>,
    ) -> Self {
        Self {
            endpoints,
            destinations,
            source,
            contents,
            metadata: <_>::default(),
        }
    }
}
