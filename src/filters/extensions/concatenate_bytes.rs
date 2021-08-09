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

use base64_serde::base64_serde_type;
use serde::{Deserialize, Serialize};

use crate::filters::prelude::*;
use crate::map_proto_enum;

crate::include_proto!("quilkin.extensions.filters.concatenate_bytes.v1alpha1");
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
    #[serde(rename = "DO_NOTHING")]
    DoNothing,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::DoNothing
    }
}

/// Config represents a [`ConcatenateBytes`] filter configuration
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Config {
    /// Whether or not to `append` or `prepend` or `do nothing` on Filter `Read`
    #[serde(default)]
    on_read: Strategy,
    /// Whether or not to `append` or `prepend` or `do nothing` on Filter `Write`
    #[serde(default)]
    on_write: Strategy,

    #[serde(with = "Base64Standard")]
    bytes: Vec<u8>,
}

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> Result<Self, Self::Error> {
        let on_read = p
            .on_read
            .map(|strategy| {
                map_proto_enum!(
                    value = strategy.value,
                    field = "on_read",
                    proto_enum_type = ProtoStrategy,
                    target_enum_type = Strategy,
                    variants = [DoNothing, Append, Prepend]
                )
            })
            .transpose()?
            .unwrap_or_else(Strategy::default);

        let on_write = p
            .on_write
            .map(|strategy| {
                map_proto_enum!(
                    value = strategy.value,
                    field = "on_write",
                    proto_enum_type = ProtoStrategy,
                    target_enum_type = Strategy,
                    variants = [DoNothing, Append, Prepend]
                )
            })
            .transpose()?
            .unwrap_or_else(Strategy::default);

        Ok(Self {
            on_read,
            on_write,
            bytes: p.bytes,
        })
    }
}

/// The `ConcatenateBytes` filter's job is to add a byte packet to either the beginning or end of each UDP packet that passes
/// through. This is commonly used to provide an auth token to each packet, so they can be routed appropriately.
#[crate::filter("quilkin.extensions.filters.concatenate_bytes.v1alpha1.ConcatenateBytes")]
struct ConcatenateBytes {
    on_read: Strategy,
    on_write: Strategy,
    bytes: Vec<u8>,
}

pub struct ConcatBytesFactory;

impl Default for ConcatBytesFactory {
    fn default() -> Self {
        Self {}
    }
}

impl FilterFactory for ConcatBytesFactory {
    fn name(&self) -> &'static str {
        ConcatenateBytes::FILTER_NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(ConcatenateBytes::new(
            self.require_config(args.config)?
                .deserialize::<Config, ProtoConfig>(self.name())?,
        )))
    }
}

impl ConcatenateBytes {
    pub fn new(config: Config) -> Self {
        ConcatenateBytes {
            on_read: config.on_read,
            on_write: config.on_write,
            bytes: config.bytes,
        }
    }
}

impl Filter for ConcatenateBytes {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        match self.on_read {
            Strategy::Append => {
                ctx.contents.extend(self.bytes.iter());
            }
            Strategy::Prepend => {
                ctx.contents.splice(..0, self.bytes.iter().cloned());
            }
            Strategy::DoNothing => {}
        }

        Some(ctx.into())
    }

    fn write(&self, mut ctx: WriteContext) -> Option<WriteResponse> {
        match self.on_write {
            Strategy::Append => {
                ctx.contents.extend(self.bytes.iter());
            }
            Strategy::Prepend => {
                ctx.contents.splice(..0, self.bytes.iter().cloned());
            }
            Strategy::DoNothing => {}
        }

        Some(ctx.into())
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use serde_yaml::{Mapping, Value};

    use crate::cluster::Endpoint;
    use crate::config::Endpoints;
    use crate::filters::{CreateFilterArgs, Filter, FilterFactory, ReadContext, WriteContext};
    use crate::test_utils::{assert_filter_read_no_change, assert_write_no_change};

    use super::quilkin::extensions::filters::concatenate_bytes::v1alpha1::{
        concatenate_bytes::{Strategy as ProtoStrategy, StrategyValue},
        ConcatenateBytes as ProtoConfig,
    };
    use super::{ConcatBytesFactory, ConcatenateBytes, Config, Strategy};
    use prometheus::Registry;

    #[test]
    fn convert_proto_config() {
        let test_cases = vec![
            (
                "should succeed when all valid values are provided",
                ProtoConfig {
                    on_write: Some(StrategyValue {
                        value: ProtoStrategy::Append as i32,
                    }),
                    on_read: Some(StrategyValue {
                        value: ProtoStrategy::DoNothing as i32,
                    }),
                    bytes: "abc".into(),
                },
                Some(Config {
                    on_write: Strategy::Append,
                    on_read: Strategy::DoNothing,
                    bytes: "abc".into(),
                }),
            ),
            (
                "should fail when invalid strategy is provided",
                ProtoConfig {
                    on_read: Some(StrategyValue { value: 42 }),
                    on_write: None,
                    bytes: "abc".into(),
                },
                None,
            ),
            (
                "should use correct default values",
                ProtoConfig {
                    on_write: None,
                    on_read: None,
                    bytes: "abc".into(),
                },
                Some(Config {
                    on_write: Strategy::default(),
                    on_read: Strategy::default(),
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
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map.clone())),
            ))
            .unwrap();
        assert_read_with_filter(filter.as_ref(), "abc");
        assert_write_with_filter(filter.as_ref(), "abc");

        map.insert(
            Value::String("on_read".into()),
            Value::String("APPEND".into()),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map.clone())),
            ))
            .unwrap();
        assert_read_with_filter(filter.as_ref(), "abchello");

        map.insert(
            Value::String("on_read".into()),
            Value::String("PREPEND".into()),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .unwrap();

        assert_read_with_filter(filter.as_ref(), "helloabc");

        let mut map = Mapping::new();
        map.insert(
            Value::String("bytes".into()),
            Value::String(base64::encode(b"hello")),
        );
        map.insert(
            Value::String("on_write".into()),
            Value::String("APPEND".into()),
        );
        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map.clone())),
            ))
            .unwrap();

        assert_write_with_filter(filter.as_ref(), "abchello");

        map.insert(
            Value::String("on_write".into()),
            Value::String("PREPEND".into()),
        );
        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .unwrap();
        assert_write_with_filter(filter.as_ref(), "helloabc");
    }

    #[test]
    fn factory_invalid_config() {
        let factory = ConcatBytesFactory::default();
        let mut map = Mapping::new();

        let result = factory.create_filter(CreateFilterArgs::fixed(
            Registry::default(),
            Some(&Value::Mapping(map.clone())),
        ));
        assert!(result.is_err());

        // broken strategy
        map.insert(
            Value::String("strategy".into()),
            Value::String("WRONG".into()),
        );

        let result = factory.create_filter(CreateFilterArgs::fixed(
            Registry::default(),
            Some(&Value::Mapping(map)),
        ));
        assert!(result.is_err());
    }

    #[test]
    fn write_create_append() {
        let on_read = Strategy::Append;
        let expected = "abchello";
        assert_create_read_filter(on_read, expected);
    }

    #[test]
    fn write_create_prepend() {
        let on_read = Strategy::Prepend;
        let expected = "helloabc";
        assert_create_read_filter(on_read, expected);
    }

    #[test]
    fn write_append() {
        let config = Config {
            on_read: Default::default(),
            on_write: Strategy::Append,
            bytes: b"hello".to_vec(),
        };
        let filter = ConcatenateBytes::new(config);
        assert_write_with_filter(&filter, "abchello");
    }

    #[test]
    fn write_prepend() {
        let config = Config {
            on_read: Default::default(),
            on_write: Strategy::Prepend,
            bytes: b"hello".to_vec(),
        };
        let filter = ConcatenateBytes::new(config);
        assert_write_with_filter(&filter, "helloabc");
    }

    #[test]
    fn read_noop() {
        let config = Config {
            on_read: Default::default(),
            on_write: Default::default(),
            bytes: vec![],
        };
        let filter = ConcatenateBytes::new(config);
        assert_filter_read_no_change(&filter);
    }

    #[test]
    fn write_noop() {
        let config = Config {
            on_read: Default::default(),
            on_write: Default::default(),
            bytes: vec![],
        };
        let filter = ConcatenateBytes::new(config);
        assert_write_no_change(&filter);
    }

    fn assert_create_read_filter(on_read: Strategy, expected: &str) {
        let contents = b"hello".to_vec();
        let config = Config {
            on_read,
            on_write: Default::default(),
            bytes: contents,
        };
        let filter = ConcatenateBytes::new(config);

        assert_read_with_filter(&filter, expected);
    }

    fn assert_read_with_filter<F>(filter: &F, expected: &str)
    where
        F: Filter + ?Sized,
    {
        let endpoints = vec![Endpoint::new("127.0.0.1:81".parse().unwrap())];
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

    fn assert_write_with_filter<F>(filter: &F, expected: &str)
    where
        F: Filter + ?Sized,
    {
        let response = filter
            .write(WriteContext::new(
                &Endpoint::new("127.0.0.1:81".parse().unwrap()),
                "127.0.0.1:80".parse().unwrap(),
                "127.0.0.1:82".parse().unwrap(),
                b"abc".to_vec(),
            ))
            .unwrap();

        assert_eq!(expected.to_string().into_bytes(), response.contents);
    }
}
