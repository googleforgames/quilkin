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

use std::{any::Any, collections::HashMap, net::SocketAddr, sync::Arc};

use crate::endpoint::UpstreamEndpoints;
#[cfg(doc)]
use crate::filters::Filter;

/// Shared state between [`Filter`]s during processing for a single packet.
type DynamicMetadata = HashMap<Arc<String>, Box<dyn Any + Send>>;

/// The input arguments to [`Filter::read`].
#[non_exhaustive]
pub struct ReadContext {
    /// The upstream endpoints that the packet will be forwarded to.
    pub endpoints: UpstreamEndpoints,
    /// The source of the received packet.
    pub from: SocketAddr,
    /// Contents of the received packet.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another.
    pub metadata: DynamicMetadata,
}

impl ReadContext {
    /// Creates a new [`ReadContext`].
    pub fn new(endpoints: UpstreamEndpoints, from: SocketAddr, contents: Vec<u8>) -> Self {
        Self {
            endpoints,
            from,
            contents,
            metadata: HashMap::new(),
        }
    }

    /// Creates a new [`ReadContext`] from a given [`ReadResponse`].
    pub fn with_response(from: SocketAddr, response: ReadResponse) -> Self {
        Self {
            endpoints: response.endpoints,
            from,
            contents: response.contents,
            metadata: response.metadata,
        }
    }
}

impl From<ReadContext> for ReadResponse {
    fn from(ctx: ReadContext) -> Self {
        Self {
            endpoints: ctx.endpoints,
            contents: ctx.contents,
            metadata: ctx.metadata,
        }
    }
}

/// The output of [`Filter::read`].
///
/// New instances are created from [`ReadContext`].
///
/// ```rust
/// # use quilkin::filters::{ReadContext, ReadResponse};
///   fn read(ctx: ReadContext) -> Option<ReadResponse> {
///       Some(ctx.into())
///   }
/// ```
#[non_exhaustive]
pub struct ReadResponse {
    /// The upstream endpoints that the packet should be forwarded to.
    pub endpoints: UpstreamEndpoints,
    /// Contents of the packet to be forwarded.
    pub contents: Vec<u8>,
    /// Arbitrary values that can be passed from one filter to another
    pub metadata: DynamicMetadata,
}
