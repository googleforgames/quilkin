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

use base64_serde::base64_serde_type;
use serde::{Deserialize, Serialize};

use crate::extensions::{
    CreateFilterArgs, DownstreamContext, DownstreamResponse, Error, Filter, FilterFactory,
};

base64_serde_type!(Base64Standard, base64::STANDARD);

#[derive(Serialize, Deserialize, Debug)]
enum Strategy {
    #[serde(rename = "APPEND")]
    Append,
    #[serde(rename = "PREPEND")]
    Prepend,
}

/// Config represents ConcatToken's configuration
#[derive(Serialize, Deserialize, Debug)]
struct Config {
    /// Whether or not to `append` or `prepend` the value to the filtered packet
    #[serde(default)]
    strategy: Strategy,

    #[serde(with = "Base64Standard")]
    bytes: Vec<u8>,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::Append
    }
}

/// The `ConcatenateBytes` filter's job is to add a byte packet to either the beginning or end of each UDP packet that passes
/// through. This is commonly used to provide an auth token to each packet, so they can be routed appropriately.
struct ConcatenateBytes {
    strategy: Strategy,
    bytes: Vec<u8>,
}

pub struct ConcatBytesFactory;

impl Default for ConcatBytesFactory {
    fn default() -> Self {
        Self {}
    }
}

impl FilterFactory for ConcatBytesFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.concatenate_bytes.v1alpha1.ConcatenateBytes".into()
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Config = serde_yaml::to_string(&args.config)
            .and_then(|raw_config| serde_yaml::from_str(raw_config.as_str()))
            .map_err(|err| Error::DeserializeFailed(err.to_string()))?;

        Ok(Box::new(ConcatenateBytes::new(config)))
    }
}

impl ConcatenateBytes {
    pub fn new(config: Config) -> Self {
        ConcatenateBytes {
            strategy: config.strategy,
            bytes: config.bytes,
        }
    }
}

impl Filter for ConcatenateBytes {
    fn on_downstream_receive(&self, mut ctx: DownstreamContext) -> Option<DownstreamResponse> {
        match self.strategy {
            Strategy::Append => {
                ctx.contents.extend(self.bytes.iter());
            }
            Strategy::Prepend => {
                ctx.contents.splice(..0, self.bytes.iter().cloned());
            }
        }

        Some(ctx.into())
    }
}

#[cfg(test)]
mod tests {
    use serde_yaml::{Mapping, Value};

    use crate::config::{ConnectionConfig, EndPoint};
    use crate::test_utils::assert_filter_on_downstream_receive_no_change;

    use super::*;

    #[test]
    fn factory_valid_config() {
        let factory = ConcatBytesFactory::default();
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let mut map = Mapping::new();

        // default strategy
        map.insert(
            Value::String("bytes".into()),
            Value::String(base64::encode(b"hello")),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::new(
                &connection,
                Some(&Value::Mapping(map.clone())),
            ))
            .unwrap();
        assert_with_filter(filter.as_ref(), "abchello");

        // specific append
        map.insert(
            Value::String("strategy".into()),
            Value::String("APPEND".into()),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::new(
                &connection,
                Some(&Value::Mapping(map.clone())),
            ))
            .unwrap();
        assert_with_filter(filter.as_ref(), "abchello");

        // specific prepend
        map.insert(
            Value::String("strategy".into()),
            Value::String("PREPEND".into()),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::new(
                &connection,
                Some(&Value::Mapping(map)),
            ))
            .unwrap();

        assert_with_filter(filter.as_ref(), "helloabc");
    }

    #[test]
    fn factory_invalid_config() {
        let factory = ConcatBytesFactory::default();
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let mut map = Mapping::new();

        let result = factory.create_filter(CreateFilterArgs::new(
            &connection,
            Some(&Value::Mapping(map.clone())),
        ));
        assert!(result.is_err());

        // broken strategy
        map.insert(
            Value::String("strategy".into()),
            Value::String("WRONG".into()),
        );

        let result = factory.create_filter(CreateFilterArgs::new(
            &connection,
            Some(&Value::Mapping(map)),
        ));
        assert!(result.is_err());
    }

    #[test]
    fn on_downstream_receive_append() {
        let strategy = Strategy::Append;
        let expected = "abchello";
        assert_create_filter(strategy, expected);
    }

    #[test]
    fn on_downstream_receive_prepend() {
        let strategy = Strategy::Prepend;
        let expected = "helloabc";
        assert_create_filter(strategy, expected);
    }

    #[test]
    fn on_upstream_receive() {
        let config = Config {
            strategy: Default::default(),
            bytes: vec![],
        };
        let filter = ConcatenateBytes::new(config);
        assert_filter_on_downstream_receive_no_change(&filter);
    }

    fn assert_create_filter(strategy: Strategy, expected: &str) {
        let contents = b"hello".to_vec();
        let config = Config {
            strategy,
            bytes: contents,
        };
        let filter = ConcatenateBytes::new(config);

        assert_with_filter(&filter, expected);
    }

    fn assert_with_filter<F>(filter: &F, expected: &str)
    where
        F: Filter + ?Sized,
    {
        let endpoints = vec![EndPoint {
            name: "e1".to_string(),
            address: "127.0.0.1:81".parse().unwrap(),
            connection_ids: vec![],
        }];
        let response = filter
            .on_downstream_receive(DownstreamContext::new(
                endpoints.clone(),
                "127.0.0.1:80".parse().unwrap(),
                "abc".to_string().into_bytes(),
            ))
            .unwrap();

        assert_eq!(endpoints, response.endpoints);
        assert_eq!(expected.to_string().into_bytes(), response.contents);
    }
}
