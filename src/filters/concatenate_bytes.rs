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

crate::include_proto!("quilkin.filters.concatenate_bytes.v1alpha1");

mod config;

use crate::filters::prelude::*;

use self::quilkin::filters::concatenate_bytes::v1alpha1 as proto;
pub use config::{Config, Strategy};

/// The `ConcatenateBytes` filter's job is to add a byte packet to either the
/// beginning or end of each UDP packet that passes through. This is commonly
/// used to provide an auth token to each packet, so they can be
/// routed appropriately.
pub struct ConcatenateBytes {
    on_read: Strategy,
    on_write: Strategy,
    bytes: Vec<u8>,
}

impl ConcatenateBytes {
    pub fn new(config: Config) -> Self {
        ConcatenateBytes {
            on_read: config.on_read,
            on_write: config.on_write,
            bytes: config.bytes,
        }
    }
}

#[async_trait::async_trait]
impl Filter for ConcatenateBytes {
    async fn read(&self, ctx: &mut ReadContext) -> Result<(), FilterError> {
        match self.on_read {
            Strategy::Append => {
                ctx.contents.extend(self.bytes.iter());
            }
            Strategy::Prepend => {
                ctx.contents.splice(..0, self.bytes.iter().cloned());
            }
            Strategy::DoNothing => {}
        }

        Ok(())
    }

    async fn write(&self, ctx: &mut WriteContext) -> Result<(), FilterError> {
        match self.on_write {
            Strategy::Append => {
                ctx.contents.extend(self.bytes.iter());
            }
            Strategy::Prepend => {
                ctx.contents.splice(..0, self.bytes.iter().cloned());
            }
            Strategy::DoNothing => {}
        }

        Ok(())
    }
}

impl StaticFilter for ConcatenateBytes {
    const NAME: &'static str = "quilkin.filters.concatenate_bytes.v1alpha1.ConcatenateBytes";
    type Configuration = Config;
    type BinaryConfiguration = proto::ConcatenateBytes;

    fn try_from_config(config: Option<Self::Configuration>) -> Result<Self, CreationError> {
        Ok(ConcatenateBytes::new(Self::ensure_config_exists(config)?))
    }
}
