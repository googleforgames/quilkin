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

#[allow(warnings, clippy::all)]
// ANCHOR: include_proto
mod proto {
    tonic::include_proto!("greet");
}
// ANCHOR_END: include_proto
use quilkin::filters::prelude::*;

use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

// ANCHOR: serde_config
#[derive(Serialize, Deserialize, Debug, schemars::JsonSchema)]
struct Config {
    greeting: String,
}
// ANCHOR_END: serde_config

// ANCHOR: TryFrom
impl TryFrom<proto::Greet> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: proto::Greet) -> Result<Self, Self::Error> {
        Ok(Self {
            greeting: p.greeting,
        })
    }
}

impl From<Config> for proto::Greet {
    fn from(config: Config) -> Self {
        Self {
            greeting: config.greeting,
        }
    }
}
// ANCHOR_END: TryFrom

// ANCHOR: filter
struct Greet {
    config: Config,
}

#[async_trait::async_trait]
impl Filter for Greet {
    async fn read(&self, ctx: &mut ReadContext) -> Result<(), FilterError> {
        ctx.contents
            .splice(0..0, format!("{} ", self.config.greeting).into_bytes());
        Ok(())
    }
    async fn write(&self, ctx: &mut WriteContext) -> Result<(), FilterError> {
        ctx.contents
            .splice(0..0, format!("{} ", self.config.greeting).into_bytes());
        Ok(())
    }
}
// ANCHOR_END: filter

// ANCHOR: factory
use quilkin::filters::StaticFilter;

impl StaticFilter for Greet {
    const NAME: &'static str = "greet.v1";
    type Configuration = Config;
    type BinaryConfiguration = proto::Greet;

    fn try_from_config(config: Option<Self::Configuration>) -> Result<Self, CreationError> {
        Ok(Self {
            config: Self::ensure_config_exists(config)?,
        })
    }
}
// ANCHOR_END: factory

// ANCHOR: run
#[tokio::main]
async fn main() -> quilkin::Result<()> {
    quilkin::filters::FilterRegistry::register(vec![Greet::factory()].into_iter());

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
    let proxy = quilkin::Proxy::default();
    let config = quilkin::Config::default();
    config.filters.store(std::sync::Arc::new(
        vec![quilkin::config::Filter {
            name: Greet::NAME.into(),
            label: None,
            config: None,
        }]
        .try_into()?,
    ));
    config.clusters.modify(|map| {
        map.insert_default(vec![quilkin::endpoint::Endpoint::new(
            (std::net::Ipv4Addr::LOCALHOST, 4321).into(),
        )])
    });

    proxy.run(config.into(), shutdown_rx).await
}
// ANCHOR_END: run
