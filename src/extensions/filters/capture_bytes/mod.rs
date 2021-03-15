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
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use slog::{o, warn, Logger};

use metrics::Metrics;

use crate::extensions::filters::ConvertProtoConfigError;
use crate::extensions::filters::CAPTURED_BYTES;
use crate::extensions::{
    CreateFilterArgs, Error, Filter, FilterFactory, ReadContext, ReadResponse,
};
use crate::map_proto_enum;
use proto::quilkin::extensions::filters::capture_bytes::v1alpha1::{
    capture_bytes::Strategy as ProtoStrategy, CaptureBytes as ProtoConfig,
};

mod metrics;
mod proto;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
/// Strategy to apply for acquiring a set of bytes in the UDP packet
enum Strategy {
    #[serde(rename = "PREFIX")]
    /// Looks for the set of bytes at the beginning of the packet
    Prefix,
    #[serde(rename = "SUFFIX")]
    /// Look for the set of bytes at the end of the packet
    Suffix,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Config {
    #[serde(default)]
    strategy: Strategy,
    /// the number of bytes to capture
    #[serde(rename = "size")]
    size: usize,
    /// the key to use when storing the captured bytes in the filter context
    #[serde(rename = "metadataKey")]
    #[serde(default = "default_metadata_key")]
    metadata_key: String,
    /// whether or not to remove the set of the bytes from the packet once captured
    #[serde(default = "default_remove")]
    remove: bool,
}

/// default value for [`Config::remove`].
fn default_remove() -> bool {
    false
}

/// default value for the context key in the Config
fn default_metadata_key() -> String {
    CAPTURED_BYTES.into()
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::Suffix
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
                    variants = [Suffix, Prefix]
                )
            })
            .transpose()?
            .unwrap_or_else(Strategy::default);

        Ok(Self {
            strategy,
            size: p.size as usize,
            metadata_key: p.metadata_key.unwrap_or_else(default_metadata_key),
            remove: p.remove.unwrap_or_else(default_remove),
        })
    }
}

pub struct CaptureBytesFactory {
    log: Logger,
}

impl CaptureBytesFactory {
    pub fn new(base: &Logger) -> Self {
        CaptureBytesFactory { log: base.clone() }
    }
}

impl FilterFactory for CaptureBytesFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.capture_bytes.v1alpha1.CaptureBytes".into()
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(CaptureBytes::new(
            &self.log,
            self.require_config(args.config)?
                .deserialize::<Config, ProtoConfig>(self.name().as_str())?,
            Metrics::new(&args.metrics_registry)?,
        )))
    }
}

struct CaptureBytes {
    log: Logger,
    capture: Box<dyn Capture + Sync + Send>,
    /// metrics reporter for this filter.
    metrics: Metrics,
    metadata_key: Arc<String>,
    size: usize,
    remove: bool,
}

impl CaptureBytes {
    fn new(base: &Logger, config: Config, metrics: Metrics) -> Self {
        let capture: Box<dyn Capture + Sync + Send> = match config.strategy {
            Strategy::Prefix => Box::new(Prefix {}),
            Strategy::Suffix => Box::new(Suffix {}),
        };

        CaptureBytes {
            log: base.new(o!("source" => "extensions::CaptureBytes")),
            capture,
            metrics,
            metadata_key: Arc::new(config.metadata_key),
            size: config.size,
            remove: config.remove,
        }
    }
}

impl Filter for CaptureBytes {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        // if the capture size is bigger than the packet size, then we drop the packet,
        // and occasionally warn
        if ctx.contents.len() < self.size {
            if self.metrics.packets_dropped_total.get() % 1000 == 0 {
                warn!(
                    self.log,
                    "packets are being dropped due to their length being less than {} bytes",
                    self.size; "count" => self.metrics.packets_dropped_total.get()
                );
            }
            self.metrics.packets_dropped_total.inc();
            return None;
        }
        let token = self
            .capture
            .capture(&mut ctx.contents, self.size, self.remove);

        ctx.metadata
            .insert(self.metadata_key.clone(), Box::new(token));

        Some(ctx.into())
    }
}

/// Trait to implement different strategies for capturing packet data
trait Capture {
    /// Capture the packet data from the contents. If remove is true, contents will be altered to
    /// not have the retrieved set of bytes.
    /// Returns the captured bytes.
    fn capture(&self, contents: &mut Vec<u8>, size: usize, remove: bool) -> Vec<u8>;
}

struct Suffix;
impl Capture for Suffix {
    fn capture(&self, contents: &mut Vec<u8>, size: usize, remove: bool) -> Vec<u8> {
        if remove {
            return contents.split_off(contents.len() - size);
        }

        contents
            .iter()
            .skip(contents.len() - size)
            .cloned()
            .collect::<Vec<u8>>()
    }
}

struct Prefix;
impl Capture for Prefix {
    fn capture(&self, contents: &mut Vec<u8>, size: usize, remove: bool) -> Vec<u8> {
        if remove {
            return contents.drain(..size).collect();
        }

        contents.iter().cloned().take(size).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::sync::Arc;

    use prometheus::Registry;
    use serde_yaml::{Mapping, Value};

    use crate::config::Endpoints;
    use crate::test_utils::{assert_write_no_change, logger};

    use super::{
        default_metadata_key, default_remove, Capture, CaptureBytes, CaptureBytesFactory, Config,
        Metrics, Prefix, Strategy, Suffix,
    };

    use super::proto::quilkin::extensions::filters::capture_bytes::v1alpha1::{
        capture_bytes::{Strategy as ProtoStrategy, StrategyValue},
        CaptureBytes as ProtoConfig,
    };
    use crate::cluster::Endpoint;
    use crate::extensions::filters::CAPTURED_BYTES;
    use crate::extensions::{CreateFilterArgs, Filter, FilterFactory, ReadContext};

    const TOKEN_KEY: &str = "TOKEN";

    fn capture_bytes(config: Config) -> CaptureBytes {
        CaptureBytes::new(
            &logger(),
            config,
            Metrics::new(&Registry::default()).unwrap(),
        )
    }

    #[test]
    fn convert_proto_config() {
        let test_cases = vec![
            (
                "should succeed when all valid values are provided",
                ProtoConfig {
                    strategy: Some(StrategyValue {
                        value: ProtoStrategy::Suffix as i32,
                    }),
                    size: 42,
                    metadata_key: Some("foobar".into()),
                    remove: Some(true),
                },
                Some(Config {
                    strategy: Strategy::Suffix,
                    size: 42,
                    metadata_key: "foobar".into(),
                    remove: true,
                }),
            ),
            (
                "should fail when invalid strategy is provided",
                ProtoConfig {
                    strategy: Some(StrategyValue { value: 42 }),
                    size: 42,
                    metadata_key: Some("foobar".into()),
                    remove: Some(true),
                },
                None,
            ),
            (
                "should use correct default values",
                ProtoConfig {
                    strategy: None,
                    size: 42,
                    metadata_key: None,
                    remove: None,
                },
                Some(Config {
                    strategy: Strategy::default(),
                    size: 42,
                    metadata_key: default_metadata_key(),
                    remove: default_remove(),
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
    fn factory_valid_config_all() {
        let factory = CaptureBytesFactory::new(&logger());
        let mut map = Mapping::new();
        map.insert(
            Value::String("strategy".into()),
            Value::String("SUFFIX".into()),
        );
        map.insert(
            Value::String("metadataKey".into()),
            Value::String(TOKEN_KEY.into()),
        );
        map.insert(Value::String("size".into()), Value::Number(3.into()));
        map.insert(Value::String("remove".into()), Value::Bool(true));

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .unwrap();
        assert_end_strategy(filter.as_ref(), TOKEN_KEY, true);
    }

    #[test]
    fn factory_valid_config_defaults() {
        let factory = CaptureBytesFactory::new(&logger());
        let mut map = Mapping::new();
        map.insert(Value::String("size".into()), Value::Number(3.into()));
        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .unwrap();
        assert_end_strategy(filter.as_ref(), CAPTURED_BYTES, false);
    }

    #[test]
    fn factory_invalid_config() {
        let factory = CaptureBytesFactory::new(&logger());
        let mut map = Mapping::new();
        map.insert(Value::String("size".into()), Value::String("WRONG".into()));

        let result = factory.create_filter(CreateFilterArgs::fixed(
            Registry::default(),
            Some(&Value::Mapping(map)),
        ));
        assert!(result.is_err(), "Should be an error");
    }

    #[test]
    fn read() {
        let config = Config {
            strategy: Strategy::Suffix,
            metadata_key: TOKEN_KEY.into(),
            size: 3,
            remove: true,
        };
        let filter = capture_bytes(config);
        assert_end_strategy(&filter, TOKEN_KEY, true);
    }

    #[test]
    fn read_overflow_capture_size() {
        let config = Config {
            strategy: Strategy::Suffix,
            metadata_key: TOKEN_KEY.into(),
            size: 99,
            remove: true,
        };
        let filter = capture_bytes(config);
        let endpoints = vec![Endpoint::from_address("127.0.0.1:81".parse().unwrap())];
        let response = filter.read(ReadContext::new(
            Endpoints::new(endpoints).unwrap().into(),
            "127.0.0.1:80".parse().unwrap(),
            "abc".to_string().into_bytes(),
        ));

        assert!(response.is_none());
        let count = filter.metrics.packets_dropped_total.get();
        assert_eq!(1, count);
    }

    #[test]
    fn write() {
        let config = Config {
            strategy: Strategy::Suffix,
            metadata_key: TOKEN_KEY.into(),
            size: 0,
            remove: false,
        };
        let filter = capture_bytes(config);
        assert_write_no_change(&filter);
    }

    #[test]
    fn end_capture() {
        let end = Suffix {};
        let mut contents = b"helloabc".to_vec();
        let result = end.capture(&mut contents, 3, false);
        assert_eq!(b"abc".to_vec(), result);
        assert_eq!(b"helloabc".to_vec(), contents);

        let result = end.capture(&mut contents, 3, true);
        assert_eq!(b"abc".to_vec(), result);
        assert_eq!(b"hello".to_vec(), contents);
    }

    #[test]
    fn beginning_capture() {
        let beg = Prefix {};
        let mut contents = b"abchello".to_vec();

        let result = beg.capture(&mut contents, 3, false);
        assert_eq!(b"abc".to_vec(), result);
        assert_eq!(b"abchello".to_vec(), contents);

        let result = beg.capture(&mut contents, 3, true);
        assert_eq!(b"abc".to_vec(), result);
        assert_eq!(b"hello".to_vec(), contents);
    }

    fn assert_end_strategy<F>(filter: &F, key: &str, remove: bool)
    where
        F: Filter + ?Sized,
    {
        let endpoints = vec![Endpoint::from_address("127.0.0.1:81".parse().unwrap())];
        let response = filter
            .read(ReadContext::new(
                Endpoints::new(endpoints).unwrap().into(),
                "127.0.0.1:80".parse().unwrap(),
                "helloabc".to_string().into_bytes(),
            ))
            .unwrap();

        if remove {
            assert_eq!(b"hello".to_vec(), response.contents);
        } else {
            assert_eq!(b"helloabc".to_vec(), response.contents);
        }

        let token = response
            .metadata
            .get(&Arc::new(key.into()))
            .unwrap()
            .downcast_ref::<Vec<u8>>()
            .unwrap();
        assert_eq!(b"abc", token.as_slice());
    }
}
