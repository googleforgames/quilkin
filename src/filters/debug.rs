/*
 * Copyright 2020 Google LLC
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
use slog::o;

use crate::filters::prelude::*;

crate::include_proto!("quilkin.extensions.filters.debug.v1alpha1");
use self::quilkin::extensions::filters::debug::v1alpha1::Debug as ProtoDebug;
use crate::info;
use crate::log::SharedLogger;

/// Debug logs all incoming and outgoing packets
struct Debug {
    log: SharedLogger,
}

pub const NAME: &str = "quilkin.extensions.filters.debug.v1alpha1.Debug";

/// Creates a new factory for generating debug filters.
pub fn factory(base: &SharedLogger) -> DynFilterFactory {
    Box::from(DebugFactory::new(base))
}

impl Debug {
    /// Constructor for the Debug. Pass in a "id" to append a string to your log messages from this
    /// Filter.
    fn new(base: &SharedLogger, id: Option<String>) -> Self {
        let log = match id {
            None => base.child(o!("source" => "extensions::Debug")),
            Some(id) => base.child(o!("source" => "extensions::Debug", "id" => id)),
        };

        Debug { log }
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
        Err(_) => String::from("error decoding packet as UTF-8"),
    }
}

/// Factory for the Debug
struct DebugFactory {
    log: SharedLogger,
}

impl DebugFactory {
    pub fn new(base: &SharedLogger) -> Self {
        DebugFactory { log: base.clone() }
    }
}

impl FilterFactory for DebugFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
        let config: Option<(_, Config)> = args
            .config
            .map(|config| config.deserialize::<Config, ProtoDebug>(self.name()))
            .transpose()?;
        let (config_json, config) = config
            .map(|(config_json, config)| (config_json, Some(config)))
            .unwrap_or_else(|| (serde_json::Value::Null, None));
        let filter = Debug::new(&self.log, config.and_then(|cfg| cfg.id));

        Ok(FilterInstance::new(
            config_json,
            Box::new(filter) as Box<dyn Filter>,
        ))
    }
}

/// A Debug filter's configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// Identifier that will be optionally included with each log message.
    pub id: Option<String>,
}

impl TryFrom<ProtoDebug> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoDebug) -> Result<Self, Self::Error> {
        Ok(Config { id: p.id })
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::Mapping;
    use serde_yaml::Value;

    use crate::test_utils::{assert_filter_read_no_change, assert_write_no_change};

    use super::*;
    use crate::log::test_logger;
    use prometheus::Registry;

    #[test]
    fn read() {
        let df = Debug::new(&test_logger(), None);
        assert_filter_read_no_change(&df);
    }

    #[test]
    fn write() {
        let df = Debug::new(&test_logger(), None);
        assert_write_no_change(&df);
    }

    #[test]
    fn from_config_with_id() {
        let log = test_logger();
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
        let log = test_logger();
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
        let log = test_logger();
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
