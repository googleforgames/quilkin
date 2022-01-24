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

crate::include_proto!("quilkin.extensions.filters.pass.v1alpha1");
use self::quilkin::extensions::filters::pass::v1alpha1 as proto;

/// Allows a packet to pass through, mostly useful in combination with
/// other filters.
struct Pass;

pub const NAME: &str = "quilkin.extensions.filters.pass.v1alpha1.Pass";

/// Creates a new factory for generating debug filters.
pub fn factory() -> DynFilterFactory {
    Box::from(PassFactory::new())
}

impl Pass {
    fn new() -> Self {
        Self
    }
}

impl Filter for Pass {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        Some(ctx.into())
    }

    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        Some(ctx.into())
    }
}

/// Factory for the Debug
struct PassFactory;

impl PassFactory {
    pub fn new() -> Self {
        Self
    }
}

impl FilterFactory for PassFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
        let config: Option<(_, Config)> = args
            .config
            .map(|config| config.deserialize::<Config, proto::Pass>(self.name()))
            .transpose()?;

        let (config_json, _) = config
            .map(|(config_json, config)| (config_json, Some(config)))
            .unwrap_or_else(|| (serde_json::Value::Null, None));

        Ok(FilterInstance::new(
            config_json,
            Box::new(Pass::new()) as Box<dyn Filter>,
        ))
    }
}

/// `pass` filter's configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct Config;

impl TryFrom<proto::Pass> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(_: proto::Pass) -> Result<Self, Self::Error> {
        Ok(Config)
    }
}
