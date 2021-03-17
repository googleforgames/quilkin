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

use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use slog::{info, o, Logger};

use crate::extensions::filter_registry::{
    CreateFilterArgs, Error, FilterFactory, ReadContext, ReadResponse, WriteContext, WriteResponse,
};
use crate::extensions::Filter;

/// Protobuf config for this filter.
mod quilkin {
    pub(crate) mod extensions {
        pub(crate) mod filters {
            pub(crate) mod debug {
                pub(crate) mod v1alpha1 {
                    #![doc(hidden)]
                    tonic::include_proto!("quilkin.extensions.filters.debug.v1alpha1");
                }
            }
        }
    }
}
use self::quilkin::extensions::filters::debug::v1alpha1::Debug as ProtoDebug;
use crate::extensions::filters::ConvertProtoConfigError;

/// Debug logs all incoming and outgoing packets
pub struct Debug {
    log: Logger,
}

impl Debug {
    /// Constructor for the Debug. Pass in a "id" to append a string to your log messages from this
    /// Filter.
    fn new(base: &Logger, id: Option<String>) -> Self {
        let log = match id {
            None => base.new(o!("source" => "extensions::Debug")),
            Some(id) => base.new(o!("source" => "extensions::Debug", "id" => id)),
        };

        Debug { log }
    }
}

/// A Debug filter's configuration.
#[derive(Serialize, Deserialize, Debug)]
struct Config {
    id: Option<String>,
}

impl TryFrom<ProtoDebug> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoDebug) -> Result<Self, Self::Error> {
        Ok(Config { id: p.id })
    }
}

/// Factory for the Debug
pub struct DebugFactory {
    log: Logger,
}

impl DebugFactory {
    pub fn new(base: &Logger) -> Self {
        DebugFactory { log: base.clone() }
    }
}

impl FilterFactory for DebugFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.debug.v1alpha1.Debug".into()
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Option<Config> = args
            .config
            .map(|config| config.deserialize::<Config, ProtoDebug>(self.name().as_str()))
            .transpose()?;
        Ok(Box::new(Debug::new(
            &self.log,
            config.and_then(|cfg| cfg.id),
        )))
    }
}

impl Filter for Debug {
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        info!(self.log, "Read filter event"; "from" => ctx.from, "contents" => packet_to_string(ctx.contents.clone()));
        Some(ctx.into())
    }

    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        info!(self.log, "Write filter event"; "endpoint" => ctx.endpoint.address,
        "from" => ctx.from,
        "to" => ctx.to,
        "contents" => packet_to_string(ctx.contents.clone()));
        Some(ctx.into())
    }
}

/// packet_to_string takes the content, and attempts to convert it to a string.
/// Returns a string of "error decoding packet" on failure.
fn packet_to_string(contents: Vec<u8>) -> String {
    match String::from_utf8(contents) {
        Ok(str) => str,
        Err(_) => String::from("error decoding packet"),
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::Mapping;
    use serde_yaml::Value;

    use crate::test_utils::{assert_filter_read_no_change, assert_write_no_change, logger};

    use super::*;
    use prometheus::Registry;

    #[test]
    fn read() {
        let df = Debug::new(&logger(), None);
        assert_filter_read_no_change(&df);
    }

    #[test]
    fn write() {
        let df = Debug::new(&logger(), None);
        assert_write_no_change(&df);
    }

    #[test]
    fn from_config_with_id() {
        let log = logger();
        let mut map = Mapping::new();
        let factory = DebugFactory::new(&log);

        map.insert(Value::from("id"), Value::from("name"));
        assert!(factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .is_ok());
    }

    #[test]
    fn from_config_without_id() {
        let log = logger();
        let mut map = Mapping::new();
        let factory = DebugFactory::new(&log);

        map.insert(Value::from("id"), Value::from("name"));
        assert!(factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .is_ok());
    }

    #[test]
    fn from_config_should_error() {
        let log = logger();
        let mut map = Mapping::new();
        let factory = DebugFactory::new(&log);

        map.insert(Value::from("id"), Value::Sequence(vec![]));
        assert!(factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map))
            ))
            .is_err());
    }
}
