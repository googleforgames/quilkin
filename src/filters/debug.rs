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

crate::include_proto!("quilkin.filters.debug.v1alpha1");

use std::convert::TryFrom;

use crate::filters::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::info;

use self::quilkin::filters::debug::v1alpha1 as proto;

/// Debug logs all incoming and outgoing packets
struct Debug {}

pub const NAME: &str = "quilkin.filters.debug.v1alpha1.Debug";

/// Creates a new factory for generating debug filters.
pub fn factory() -> DynFilterFactory {
    Box::from(DebugFactory::new())
}

impl Debug {
    /// Constructor for the Debug. Pass in a "id" to append a string to your log messages from this
    /// Filter.

    fn new(_: Option<String>) -> Self {
        Debug {}
    }
}

impl Filter for Debug {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        info!(source = ?&ctx.source, contents = ?packet_to_string(ctx.contents.clone()), "Read filter event");
        Some(ctx.into())
    }

    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        info!(endpoint = ?ctx.endpoint.address, source = ?&ctx.source,
            dest = ?&ctx.dest, contents = ?packet_to_string(ctx.contents.clone()), "Write filter event");
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
struct DebugFactory {}

impl DebugFactory {
    pub fn new() -> Self {
        DebugFactory {}
    }
}

impl FilterFactory for DebugFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn config_schema(&self) -> schemars::schema::RootSchema {
        schemars::schema_for!(Config)
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
        let config: Option<(_, Config)> = args
            .config
            .map(|config| config.deserialize::<Config, proto::Debug>(self.name()))
            .transpose()?;

        let (config_json, config) = config
            .map(|(config_json, config)| (config_json, Some(config)))
            .unwrap_or_else(|| (serde_json::Value::Null, None));
        let filter = Debug::new(config.and_then(|cfg| cfg.id));

        Ok(FilterInstance::new(
            config_json,
            Box::new(filter) as Box<dyn Filter>,
        ))
    }
}

/// A Debug filter's configuration.
#[derive(Serialize, Deserialize, Debug, schemars::JsonSchema)]
pub struct Config {
    /// Identifier that will be optionally included with each log message.
    pub id: Option<String>,
}

impl From<Config> for proto::Debug {
    fn from(config: Config) -> Self {
        Self { id: config.id }
    }
}

impl TryFrom<proto::Debug> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: proto::Debug) -> Result<Self, Self::Error> {
        Ok(Config { id: p.id })
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::{assert_filter_read_no_change, assert_write_no_change};
    use tracing_test::traced_test;

    use super::*;

    #[traced_test]
    #[test]
    fn read() {
        let df = Debug::new(None);
        assert_filter_read_no_change(&df);
        assert!(logs_contain("Read filter event"));
    }

    #[traced_test]
    #[test]
    fn write() {
        let df = Debug::new(None);
        assert_write_no_change(&df);
        assert!(logs_contain("Write filter event"));
        assert!(logs_contain("quilkin::filters::debug")); // the given name to the the logger by tracing
    }

    #[test]
    fn from_config_with_id() {
        let factory = DebugFactory::new();
        let config = serde_json::json!({
            "id": "name".to_string(),
        });

        assert!(factory
            .create_filter(CreateFilterArgs::fixed(Some(config)))
            .is_ok());
    }

    #[test]
    fn from_config_without_id() {
        let factory = DebugFactory::new();
        let config = serde_json::json!({
            "id": "name",
        });

        assert!(factory
            .create_filter(CreateFilterArgs::fixed(Some(config)))
            .is_ok());
    }

    #[test]
    fn from_config_should_error() {
        let factory = DebugFactory::new();

        let config = serde_json::json!({
            "id": {},
        });
        assert!(factory
            .create_filter(CreateFilterArgs::fixed(Some(config)))
            .is_err());
    }
}
