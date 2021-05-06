use quilkin::extensions::{ConfigType, CreateFilterArgs, Error, FilterFactory};
use quilkin::extensions::{Filter, ReadContext, ReadResponse, WriteContext, WriteResponse};
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

struct GreetFilterFactory;
impl FilterFactory for GreetFilterFactory {
    fn name(&self) -> String {
        "greet.v1".into()
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
    run(vec![Box::new(GreetFilterFactory)]).await.unwrap();
}
