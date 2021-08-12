/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

mod metrics;

crate::include_proto!("quilkin.extensions.filters.token_router.v1alpha1");

use std::convert::TryFrom;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use slog::{error, o, Logger};

use crate::{
    config::LOG_SAMPLING_RATE,
    endpoint::RetainedItems,
    filters::{metadata::CAPTURED_BYTES, prelude::*},
};

use metrics::Metrics;

use self::quilkin::extensions::filters::token_router::v1alpha1::TokenRouter as ProtoConfig;

pub const NAME: &str = "quilkin.extensions.filters.token_router.v1alpha1.TokenRouter";

/// Returns a factory for creating token routing filters.
pub fn factory(base: &Logger) -> DynFilterFactory {
    Box::from(TokenRouterFactory::new(base))
}

/// Filter that only allows packets to be passed to Endpoints that have a matching
/// connection_id to the token stored in the Filter's dynamic metadata.
struct TokenRouter {
    log: Logger,
    metadata_key: Arc<String>,
    metrics: Metrics,
}

impl TokenRouter {
    fn new(base: &Logger, config: Config, metrics: Metrics) -> Self {
        Self {
            log: base.new(o!("source" => "extensions::TokenRouter")),
            metadata_key: Arc::new(config.metadata_key),
            metrics,
        }
    }
}

/// Factory for the TokenRouter filter
struct TokenRouterFactory {
    log: Logger,
}

impl TokenRouterFactory {
    pub fn new(base: &Logger) -> Self {
        TokenRouterFactory { log: base.clone() }
    }
}

impl FilterFactory for TokenRouterFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Config = args
            .config
            .map(|config| config.deserialize::<Config, ProtoConfig>(self.name()))
            .transpose()?
            .unwrap_or_default();

        Ok(Box::new(TokenRouter::new(
            &self.log,
            config,
            Metrics::new(&args.metrics_registry)?,
        )))
    }
}

impl Filter for TokenRouter {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        match ctx.metadata.get(self.metadata_key.as_ref()) {
            None => {
                if self.metrics.packets_dropped_no_token_found.get() % LOG_SAMPLING_RATE == 0 {
                    error!(
                        self.log,
                        "Packets are being dropped as no routing token was found in filter dynamic metadata";
                        "count" => self.metrics.packets_dropped_no_token_found.get(),
                        "metadata_key" => self.metadata_key.clone()
                    );
                }
                self.metrics.packets_dropped_no_token_found.inc();
                None
            }
            Some(value) => match value.downcast_ref::<Vec<u8>>() {
                Some(token) => match ctx
                    .endpoints
                    .retain(|e| e.metadata.known.tokens.contains(token))
                {
                    RetainedItems::None => {
                        self.metrics.packets_dropped_no_endpoint_match.inc();
                        None
                    }
                    _ => Some(ctx.into()),
                },
                None => {
                    if self.metrics.packets_dropped_invalid_token.get() % LOG_SAMPLING_RATE == 0 {
                        error!(
                            self.log,
                            "Packets are being dropped as routing token has invalid type: expected Vec<u8>";
                            "count" => self.metrics.packets_dropped_invalid_token.get(),
                            "metadata_key" => self.metadata_key.clone()
                        );
                    }
                    self.metrics.packets_dropped_invalid_token.inc();
                    None
                }
            },
        }
    }

    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        Some(ctx.into())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(default)]
pub struct Config {
    /// the key to use when retrieving the token from the Filter's dynamic metadata
    #[serde(rename = "metadataKey", default = "default_metadata_key")]
    pub metadata_key: String,
}

/// Default value for [`Config::metadata_key`]
fn default_metadata_key() -> String {
    CAPTURED_BYTES.into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            metadata_key: default_metadata_key(),
        }
    }
}

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            metadata_key: p.metadata_key.unwrap_or_else(default_metadata_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::ops::Deref;
    use std::sync::Arc;

    use prometheus::Registry;
    use serde_yaml::{Mapping, Value};

    use crate::endpoint::{Endpoint, Endpoints, Metadata};
    use crate::test_utils::{assert_write_no_change, logger};

    use super::{
        default_metadata_key, Config, Metrics, ProtoConfig, TokenRouter, TokenRouterFactory,
    };
    use crate::filters::{
        metadata::CAPTURED_BYTES, CreateFilterArgs, Filter, FilterFactory, ReadContext,
    };

    const TOKEN_KEY: &str = "TOKEN";

    fn router(config: Config) -> TokenRouter {
        TokenRouter::new(
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
                    metadata_key: Some("foobar".into()),
                },
                Some(Config {
                    metadata_key: "foobar".into(),
                }),
            ),
            (
                "should use correct default values",
                ProtoConfig { metadata_key: None },
                Some(Config {
                    metadata_key: default_metadata_key(),
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
    fn factory_custom_tokens() {
        let factory = TokenRouterFactory::new(&logger());
        let mut map = Mapping::new();
        map.insert(
            Value::String("metadataKey".into()),
            Value::String(TOKEN_KEY.into()),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .unwrap();
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(Arc::new(TOKEN_KEY.into()), Box::new(b"123".to_vec()));
        assert_read(filter.deref(), ctx);
    }

    #[test]
    fn factory_empty_config() {
        let factory = TokenRouterFactory::new(&logger());
        let map = Mapping::new();

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&Value::Mapping(map)),
            ))
            .unwrap();
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(Arc::new(CAPTURED_BYTES.into()), Box::new(b"123".to_vec()));
        assert_read(filter.deref(), ctx);
    }

    #[test]
    fn factory_no_config() {
        let factory = TokenRouterFactory::new(&logger());

        let filter = factory
            .create_filter(CreateFilterArgs::fixed(Registry::default(), None))
            .unwrap();
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(Arc::new(CAPTURED_BYTES.into()), Box::new(b"123".to_vec()));
        assert_read(filter.deref(), ctx);
    }

    #[test]
    fn downstream_receive() {
        // valid key
        let config = Config {
            metadata_key: CAPTURED_BYTES.into(),
        };
        let filter = router(config);

        let mut ctx = new_ctx();
        ctx.metadata
            .insert(Arc::new(CAPTURED_BYTES.into()), Box::new(b"123".to_vec()));
        assert_read(&filter, ctx);

        // invalid key
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(Arc::new(CAPTURED_BYTES.into()), Box::new(b"567".to_vec()));

        let option = filter.read(ctx);
        assert!(option.is_none());
        assert_eq!(1, filter.metrics.packets_dropped_no_endpoint_match.get());

        // no key
        let ctx = new_ctx();
        assert!(filter.read(ctx).is_none());
        assert_eq!(1, filter.metrics.packets_dropped_no_token_found.get());

        // wrong type key
        let mut ctx = new_ctx();
        ctx.metadata.insert(
            Arc::new(CAPTURED_BYTES.into()),
            Box::new(String::from("wrong")),
        );
        assert!(filter.read(ctx).is_none());
        assert_eq!(1, filter.metrics.packets_dropped_invalid_token.get());
    }

    #[test]
    fn write() {
        let config = Config {
            metadata_key: CAPTURED_BYTES.into(),
        };
        let filter = router(config);
        assert_write_no_change(&filter);
    }

    fn new_ctx() -> ReadContext {
        let endpoint1 = Endpoint::with_metadata(
            "127.0.0.1:80".parse().unwrap(),
            Metadata {
                tokens: vec!["123".into()].into_iter().collect(),
            },
        );
        let endpoint2 = Endpoint::with_metadata(
            "127.0.0.1:90".parse().unwrap(),
            Metadata {
                tokens: vec!["456".into()].into_iter().collect(),
            },
        );

        ReadContext::new(
            Endpoints::new(vec![endpoint1, endpoint2]).unwrap().into(),
            "127.0.0.1:100".parse().unwrap(),
            b"hello".to_vec(),
        )
    }

    fn assert_read<F>(filter: &F, ctx: ReadContext)
    where
        F: Filter + ?Sized,
    {
        let result = filter.read(ctx).unwrap();

        assert_eq!(b"hello".to_vec(), result.contents);
        assert_eq!(1, result.endpoints.size());
    }
}
