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

// ANCHOR: include_proto
quilkin::include_proto!("greet");
use greet::Greet as ProtoGreet;
// ANCHOR_END: include_proto
use quilkin::filters::prelude::*;

use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

// ANCHOR: serde_config
#[derive(Serialize, Deserialize, Debug)]
struct Config {
    greeting: String,
}
// ANCHOR_END: serde_config

// ANCHOR: TryFrom
impl TryFrom<ProtoGreet> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoGreet) -> Result<Self, Self::Error> {
        Ok(Config {
            greeting: p.greeting,
        })
    }
}
// ANCHOR_END: TryFrom

// ANCHOR: filter
struct Greet(String);

impl Filter for Greet {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        ctx.contents
            .splice(0..0, format!("{} ", self.0).into_bytes());
        Some(ctx.into())
    }
    fn write(&self, mut ctx: WriteContext) -> Option<WriteResponse> {
        ctx.contents
            .splice(0..0, format!("{} ", self.0).into_bytes());
        Some(ctx.into())
    }
}
// ANCHOR_END: filter

// ANCHOR: factory
pub const NAME: &str = "greet.v1";

pub fn factory() -> DynFilterFactory {
    Box::from(GreetFilterFactory)
}

struct GreetFilterFactory;
impl FilterFactory for GreetFilterFactory {
    fn name(&self) -> &'static str {
        NAME
    }
    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let greeting = self
            .require_config(args.config)?
            .deserialize::<Config, ProtoGreet>(self.name())?;
        Ok(Box::new(Greet(greeting.greeting)))
    }
}
// ANCHOR_END: factory

// ANCHOR: run
#[tokio::main]
async fn main() {
    quilkin::run(vec![self::factory()].into_iter())
        .await
        .unwrap();
}
// ANCHOR_END: run
