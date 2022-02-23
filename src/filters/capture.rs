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

mod affix;
mod config;
mod metrics;
mod regex;

crate::include_proto!("quilkin.filters.capture.v1alpha1");

use std::sync::Arc;

use crate::{filters::prelude::*, metadata::Value};

use self::{
    affix::{Prefix, Suffix},
    metrics::Metrics,
    regex::Regex,
};

use self::quilkin::filters::capture::v1alpha1 as proto;
pub use config::{Config, Strategy};

pub const NAME: &str = "quilkin.filters.capture.v1alpha1.Capture";

/// Creates a new factory for generating capture filters.
pub fn factory() -> DynFilterFactory {
    Box::from(CaptureFactory::new())
}

/// Trait to implement different strategies for capturing packet data.
pub trait CaptureStrategy {
    /// Capture packet data from the contents, and optionally returns a value if
    /// anything was captured.
    fn capture(&self, contents: &mut Vec<u8>, metrics: &Metrics) -> Option<Value>;
}

struct Capture {
    capture: Box<dyn CaptureStrategy + Sync + Send>,
    /// metrics reporter for this filter.
    metrics: Metrics,
    metadata_key: Arc<String>,
    is_present_key: Arc<String>,
}

impl Capture {
    fn new(config: Config, metrics: Metrics) -> Self {
        Self {
            capture: config.strategy.into_capture(),
            metrics,
            is_present_key: Arc::new(config.metadata_key.clone() + "/is_present"),
            metadata_key: Arc::new(config.metadata_key),
        }
    }
}

impl Filter for Capture {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        let capture = self.capture.capture(&mut ctx.contents, &self.metrics);
        ctx.metadata
            .insert(self.is_present_key.clone(), Value::Bool(capture.is_some()));

        if let Some(value) = capture {
            ctx.metadata.insert(self.metadata_key.clone(), value);
            Some(ctx.into())
        } else {
            None
        }
    }
}

struct CaptureFactory;

impl CaptureFactory {
    pub fn new() -> Self {
        CaptureFactory
    }
}

impl FilterFactory for CaptureFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn config_schema(&self) -> schemars::schema::RootSchema {
        schemars::schema_for!(Config)
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
        let (config_json, config) = self
            .require_config(args.config)?
            .deserialize::<Config, proto::Capture>(self.name())?;
        let filter = Capture::new(config, Metrics::new()?);
        Ok(FilterInstance::new(
            config_json,
            Box::new(filter) as Box<dyn Filter>,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_yaml::{Mapping, Value as YamlValue};

    use crate::{
        endpoint::{Endpoint, Endpoints},
        filters::metadata::CAPTURED_BYTES,
        filters::prelude::*,
        metadata::Value,
        test_utils::assert_write_no_change,
    };

    use super::{
        Capture, CaptureFactory, CaptureStrategy, Config, Metrics, Prefix, Regex, Strategy, Suffix,
    };

    const TOKEN_KEY: &str = "TOKEN";

    fn capture_bytes(config: Config) -> Capture {
        Capture::new(config, Metrics::new().unwrap())
    }

    #[test]
    fn factory_valid_config_all() {
        let factory = CaptureFactory::new();
        let mut map = Mapping::new();
        map.insert(
            YamlValue::String("metadataKey".into()),
            YamlValue::String(TOKEN_KEY.into()),
        );
        map.insert(
            YamlValue::String("suffix".into()),
            YamlValue::Mapping({
                let mut map = Mapping::new();

                map.insert("size".into(), YamlValue::Number(3.into()));
                map.insert("remove".into(), YamlValue::Bool(true));

                map
            }),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(Some(YamlValue::Mapping(map))))
            .unwrap()
            .filter;
        assert_end_strategy(filter.as_ref(), TOKEN_KEY, true);
    }

    #[test]
    fn factory_valid_config_defaults() {
        let factory = CaptureFactory::new();
        let mut map = Mapping::new();
        map.insert("suffix".into(), {
            let mut map = Mapping::new();
            map.insert(
                YamlValue::String("size".into()),
                YamlValue::Number(3.into()),
            );
            map.into()
        });

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(Some(YamlValue::Mapping(map))))
            .unwrap()
            .filter;
        assert_end_strategy(filter.as_ref(), CAPTURED_BYTES, false);
    }

    #[test]
    fn factory_invalid_config() {
        let factory = CaptureFactory::new();
        let mut map = Mapping::new();
        map.insert(
            YamlValue::String("size".into()),
            YamlValue::String("WRONG".into()),
        );

        let result = factory.create_filter(CreateFilterArgs::fixed(Some(YamlValue::Mapping(map))));
        assert!(result.is_err(), "Should be an error");
    }

    #[test]
    fn read() {
        let config = Config {
            metadata_key: TOKEN_KEY.into(),
            strategy: Strategy::Suffix(Suffix {
                size: 3,
                remove: true,
            }),
        };

        let filter = capture_bytes(config);
        assert_end_strategy(&filter, TOKEN_KEY, true);
    }

    #[test]
    fn read_overflow_capture_size() {
        let config = Config {
            metadata_key: TOKEN_KEY.into(),
            strategy: Strategy::Suffix(Suffix {
                size: 99,
                remove: true,
            }),
        };
        let filter = capture_bytes(config);
        let endpoints = vec![Endpoint::new("127.0.0.1:81".parse().unwrap())];
        let response = filter.read(ReadContext::new(
            Endpoints::new(endpoints).into(),
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
            strategy: Strategy::Suffix(Suffix {
                size: 0,
                remove: false,
            }),
            metadata_key: TOKEN_KEY.into(),
        };
        let filter = capture_bytes(config);
        assert_write_no_change(&filter);
    }

    #[test]
    fn regex_capture() {
        let metrics = Metrics::new().unwrap();
        let end = Regex {
            pattern: regex::bytes::Regex::new(".{3}$").unwrap(),
        };
        let mut contents = b"helloabc".to_vec();
        let result = end.capture(&mut contents, &metrics).unwrap();
        assert_eq!(Value::Bytes(b"abc".to_vec().into()), result);
        assert_eq!(b"helloabc".to_vec(), contents);
    }

    #[test]
    fn end_capture() {
        let metrics = Metrics::new().unwrap();
        let mut end = Suffix {
            size: 3,
            remove: false,
        };
        let mut contents = b"helloabc".to_vec();
        let result = end.capture(&mut contents, &metrics).unwrap();
        assert_eq!(Value::Bytes(b"abc".to_vec().into()), result);
        assert_eq!(b"helloabc".to_vec(), contents);

        end.remove = true;

        let result = end.capture(&mut contents, &metrics).unwrap();
        assert_eq!(Value::Bytes(b"abc".to_vec().into()), result);
        assert_eq!(b"hello".to_vec(), contents);
    }

    #[test]
    fn beginning_capture() {
        let metrics = Metrics::new().unwrap();
        let mut beg = Prefix {
            size: 3,
            remove: false,
        };
        let mut contents = b"abchello".to_vec();

        let result = beg.capture(&mut contents, &metrics);
        assert_eq!(Some(Value::Bytes(b"abc".to_vec().into())), result);
        assert_eq!(b"abchello".to_vec(), contents);

        beg.remove = true;

        let result = beg.capture(&mut contents, &metrics);
        assert_eq!(Some(Value::Bytes(b"abc".to_vec().into())), result);
        assert_eq!(b"hello".to_vec(), contents);
    }

    fn assert_end_strategy<F>(filter: &F, key: &str, remove: bool)
    where
        F: Filter + ?Sized,
    {
        let endpoints = vec![Endpoint::new("127.0.0.1:81".parse().unwrap())];
        let response = filter
            .read(ReadContext::new(
                Endpoints::new(endpoints).into(),
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
            .as_bytes()
            .unwrap();
        assert_eq!(b"abc", &**token);
    }
}
