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

use base64_serde::base64_serde_type;
use serde::{Deserialize, Serialize};

use crate::extensions::filters::ConvertProtoConfigError;
use crate::extensions::{
    CreateFilterArgs, Error, Filter, FilterFactory, ReadContext, ReadResponse,
};
use crate::map_proto_enum;

mod quilkin {
    pub(crate) mod extensions {
        pub(crate) mod filters {
            pub(crate) mod concatenate_bytes {
                pub(crate) mod v1alpha1 {
                    #![doc(hidden)]
                    tonic::include_proto!("quilkin.extensions.filters.concatenate_bytes.v1alpha1");
                }
            }
        }
    }
}
use self::quilkin::extensions::filters::concatenate_bytes::v1alpha1::{
    concatenate_bytes::Strategy as ProtoStrategy, ConcatenateBytes as ProtoConfig,
};

base64_serde_type!(Base64Standard, base64::STANDARD);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum Strategy {
    #[serde(rename = "APPEND")]
    Append,
    #[serde(rename = "PREPEND")]
    Prepend,
}

/// Config represents a [`ConcatenateBytes`] filter configuration
#[derive(Serialize, Deserialize, Debug, PartialEq)]
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

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> Result<Self, Self::Error> {
        let strategy = p
            .strategy
            .map(|strategy| {
                map_proto_enum!(
                    value = strategy.value,
                    field = "strategy",
                    proto_enum_type = ProtoStrategy,
                    target_enum_type = Strategy,
                    variants = [Append, Prepend]
                )
            })
            .transpose()?
            .unwrap_or_else(Strategy::default);

        Ok(Self {
            strategy,
            bytes: p.bytes,
        })
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
        Ok(Box::new(ConcatenateBytes::new(
            self.require_config(args.config)?
                .deserialize::<Config, ProtoConfig>(self.name().as_str())?,
        )))
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
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
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
    use std::convert::TryFrom;

    use crate::config::Endpoints;
    use crate::test_utils::assert_filter_read_no_change;
    use serde_yaml::{Mapping, Value};

    use super::quilkin::extensions::filters::concatenate_bytes::v1alpha1::{
        concatenate_bytes::{Strategy as ProtoStrategy, StrategyValue},
        ConcatenateBytes as ProtoConfig,
    };
    use super::{ConcatBytesFactory, ConcatenateBytes, Config, Strategy};
    use crate::cluster::Endpoint;
    use crate::extensions::{CreateFilterArgs, Filter, FilterFactory, ReadContext};

    #[test]
    fn convert_proto_config() {
        let test_cases = vec![
            (
                "should succeed when all valid values are provided",
                ProtoConfig {
                    strategy: Some(StrategyValue {
                        value: ProtoStrategy::Append as i32,
                    }),
                    bytes: "abc".into(),
                },
                Some(Config {
                    strategy: Strategy::Append,
                    bytes: "abc".into(),
                }),
            ),
            (
                "should fail when invalid strategy is provided",
                ProtoConfig {
                    strategy: Some(StrategyValue { value: 42 }),
                    bytes: "abc".into(),
                },
                None,
            ),
            (
                "should use correct default values",
                ProtoConfig {
                    strategy: None,
                    bytes: "abc".into(),
                },
                Some(Config {
                    strategy: Strategy::default(),
                    bytes: "abc".into(),
                }),
            ),
        ];
        for (name, proto_config, expected) in test_cases {
            let result = Config::try_from(proto_config);
            assert_eq!(
                result.is_err(),
                expected.is_none(),
                "{}: error expectation does not match",
                name
            );
            if let Some(expected) = expected {
                assert_eq!(expected, result.unwrap(), "{}", name);
            }
        }
    }

    #[test]
    fn factory_valid_config() {
        let factory = ConcatBytesFactory::default();
        let mut map = Mapping::new();

        // default strategy
        map.insert(
            Value::String("bytes".into()),
            Value::String(base64::encode(b"hello")),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(Some(&Value::Mapping(map.clone()))))
            .unwrap();
        assert_with_filter(filter.as_ref(), "abchello");

        // specific append
        map.insert(
            Value::String("strategy".into()),
            Value::String("APPEND".into()),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(Some(&Value::Mapping(map.clone()))))
            .unwrap();
        assert_with_filter(filter.as_ref(), "abchello");

        // specific prepend
        map.insert(
            Value::String("strategy".into()),
            Value::String("PREPEND".into()),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(Some(&Value::Mapping(map))))
            .unwrap();

        assert_with_filter(filter.as_ref(), "helloabc");
    }

    #[test]
    fn factory_invalid_config() {
        let factory = ConcatBytesFactory::default();
        let mut map = Mapping::new();

        let result =
            factory.create_filter(CreateFilterArgs::fixed(Some(&Value::Mapping(map.clone()))));
        assert!(result.is_err());

        // broken strategy
        map.insert(
            Value::String("strategy".into()),
            Value::String("WRONG".into()),
        );

        let result = factory.create_filter(CreateFilterArgs::fixed(Some(&Value::Mapping(map))));
        assert!(result.is_err());
    }

    #[test]
    fn write_append() {
        let strategy = Strategy::Append;
        let expected = "abchello";
        assert_create_filter(strategy, expected);
    }

    #[test]
    fn write_prepend() {
        let strategy = Strategy::Prepend;
        let expected = "helloabc";
        assert_create_filter(strategy, expected);
    }

    #[test]
    fn read() {
        let config = Config {
            strategy: Default::default(),
            bytes: vec![],
        };
        let filter = ConcatenateBytes::new(config);
        assert_filter_read_no_change(&filter);
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
        let endpoints = vec![Endpoint::from_address("127.0.0.1:81".parse().unwrap())];
        let response = filter
            .read(ReadContext::new(
                Endpoints::new(endpoints.clone()).unwrap().into(),
                "127.0.0.1:80".parse().unwrap(),
                "abc".to_string().into_bytes(),
            ))
            .unwrap();

        assert_eq!(
            endpoints,
            response.endpoints.iter().cloned().collect::<Vec<_>>()
        );
        assert_eq!(expected.to_string().into_bytes(), response.contents);
    }
}
