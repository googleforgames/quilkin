/*
 * Copyright 2022 Google LLC
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

use std::convert::TryFrom;

use crate::filters::prelude::*;
use serde::{Deserialize, Serialize};

crate::include_proto!("quilkin.filters.pass.v1alpha1");
use self::quilkin::filters::pass::v1alpha1 as proto;

/// Allows a packet to pass through, mostly useful in combination with
/// other filters.
pub struct Pass;

impl Pass {
    fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Filter for Pass {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    async fn read(&self, _: &mut ReadContext) -> Result<(), FilterError> {
        Ok(())
    }

    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    async fn write(&self, _: &mut WriteContext) -> Result<(), FilterError> {
        Ok(())
    }
}

impl StaticFilter for Pass {
    const NAME: &'static str = "quilkin.filters.pass.v1alpha1.Pass";
    type Configuration = Config;
    type BinaryConfiguration = proto::Pass;

    fn try_from_config(_config: Option<Self::Configuration>) -> Result<Self, CreationError> {
        Ok(Pass::new())
    }
}

/// `pass` filter's configuration.
#[derive(Serialize, Deserialize, Debug, schemars::JsonSchema)]
pub struct Config;

impl From<Config> for proto::Pass {
    fn from(_config: Config) -> Self {
        Self {}
    }
}

impl TryFrom<proto::Pass> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(_: proto::Pass) -> Result<Self, Self::Error> {
        Ok(Config)
    }
}
