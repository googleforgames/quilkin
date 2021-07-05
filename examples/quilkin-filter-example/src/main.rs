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

use quilkin::filters::prelude::*;
use quilkin::runner::run;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    greeting: String,
}

mod greet {
    include!(concat!(env!("OUT_DIR"), "/greet.rs"));
}

pub const NAME: &str = "greet.v1";

pub fn factory() -> DynFilterFactory {
    Box::from(GreetFilterFactory)
}

struct Greet(String);

#[async_trait::async_trait]
impl Filter for Greet {
    async fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        ctx.contents
            .splice(0..0, format!("{} ", self.0).into_bytes());
        Some(ctx.into())
    }
    async fn write(&self, mut ctx: WriteContext) -> Option<WriteResponse> {
        ctx.contents
            .splice(0..0, format!("{} ", self.0).into_bytes());
        Some(ctx.into())
    }
}

struct GreetFilterFactory;
impl FilterFactory for GreetFilterFactory {
    fn name(&self) -> &'static str {
        NAME
    }
    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let greeting = match args.config.unwrap() {
            ConfigType::Static(config) => {
                serde_yaml::from_str::<Config>(serde_yaml::to_string(config).unwrap().as_str())
                    .unwrap()
                    .greeting
            }
            ConfigType::Dynamic(config) => {
                let config: greet::Greet = prost::Message::decode(Bytes::from(config.value)).unwrap();
                config.greeting
            }
        };
        Ok(Box::new(Greet(greeting)))
    }
}

#[tokio::main]
async fn main() {
    run(vec![self::factory()].into_iter()).await.unwrap();
}
