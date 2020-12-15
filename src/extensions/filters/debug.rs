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

use slog::{info, o, Logger};

use crate::extensions::filter_registry::{
    CreateFilterArgs, DownstreamContext, DownstreamResponse, Error, FilterFactory, UpstreamContext,
    UpstreamResponse,
};
use crate::extensions::Filter;

/// Protobuf config for this filter.
mod quilkin {
    pub(crate) mod extensions {
        pub(crate) mod filters {
            pub(crate) mod debug {
                pub(crate) mod v1alpha1 {
                    #![cfg(not(doctest))]
                    #![doc(hidden)]
                    tonic::include_proto!("quilkin.extensions.filters.debug.v1alpha1");
                }
            }
        }
    }
}

/// Debug logs all incoming and outgoing packets
///
/// # Configuration
///
/// ```yaml
/// local:
///   port: 7000 # the port to receive traffic to locally
/// filters:
///   - name: quilkin.extensions.filters.debug.v1alpha1.Debug
///     config:
///       id: "debug-1"
/// client:
///   addresses:
///     - 127.0.0.1:7001
/// ```
///  `config.id` (optional) adds a "id" field with a given value to each log line.
///     This can be useful to identify debug log positioning within a filter config if you have
///     multiple Debug configured.
///
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
        // pull out the Option<&Value>
        let prefix = match args.config {
            Some(serde_yaml::Value::Mapping(map)) => map.get(&serde_yaml::Value::from("id")),
            _ => None,
        };

        match prefix {
            // if no config value supplied, then no prefix, which is fine
            None => Ok(Box::new(Debug::new(&self.log, None))),
            // return an Error if the id exists but is not a string.
            Some(value) => match value.as_str() {
                None => Err(Error::FieldInvalid {
                    field: "config.id".to_string(),
                    reason: "id value should be a string".to_string(),
                }),
                Some(prefix) => Ok(Box::new(Debug::new(&self.log, Some(prefix.to_string())))),
            },
        }
    }
}

impl Filter for Debug {
    fn on_downstream_receive(&self, ctx: DownstreamContext) -> Option<DownstreamResponse> {
        info!(self.log, "on local receive"; "from" => ctx.from, "contents" => packet_to_string(ctx.contents.clone()));
        Some(ctx.into())
    }

    fn on_upstream_receive(&self, ctx: UpstreamContext) -> Option<UpstreamResponse> {
        info!(self.log, "received endpoint packet"; "endpoint" => ctx.endpoint.name.clone(),
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

    use crate::test_utils::{
        assert_filter_on_downstream_receive_no_change, assert_filter_on_upstream_receive_no_change,
        logger,
    };

    use super::*;

    #[test]
    fn on_downstream_receive() {
        let df = Debug::new(&logger(), None);
        assert_filter_on_downstream_receive_no_change(&df);
    }

    #[test]
    fn on_upstream_receive() {
        let df = Debug::new(&logger(), None);
        assert_filter_on_upstream_receive_no_change(&df);
    }

    #[test]
    fn from_config_with_id() {
        let log = logger();
        let mut map = Mapping::new();
        let factory = DebugFactory::new(&log);

        map.insert(Value::from("id"), Value::from("name"));
        assert!(factory
            .create_filter(CreateFilterArgs::new(Some(&Value::Mapping(map)),))
            .is_ok());
    }

    #[test]
    fn from_config_without_id() {
        let log = logger();
        let mut map = Mapping::new();
        let factory = DebugFactory::new(&log);

        map.insert(Value::from("id"), Value::from("name"));
        assert!(factory
            .create_filter(CreateFilterArgs::new(Some(&Value::Mapping(map)),))
            .is_ok());
    }

    #[test]
    fn from_config_should_error() {
        let log = logger();
        let mut map = Mapping::new();
        let factory = DebugFactory::new(&log);

        map.insert(Value::from("id"), Value::from(false));
        match factory.create_filter(CreateFilterArgs::new(Some(&Value::Mapping(map)))) {
            Ok(_) => unreachable!("should be an error"),
            Err(err) => {
                assert_eq!(
                    Error::FieldInvalid {
                        field: "config.id".to_string(),
                        reason: "id value should be a string".to_string()
                    }
                    .to_string(),
                    err.to_string()
                );
            }
        }
    }
}
