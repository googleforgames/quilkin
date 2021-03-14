/*
 * Copyright 2020 Google LLC All Rights Reserved.
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

use serde::{Deserialize, Serialize};
use slog::{error, o, Logger};

use crate::extensions::filters::token_router::metrics::Metrics;
use crate::extensions::filters::ConvertProtoConfigError;
use crate::extensions::filters::CAPTURED_BYTES;
use crate::extensions::{
    CreateFilterArgs, Error, Filter, FilterFactory, ReadContext, ReadResponse, WriteContext,
    WriteResponse,
};
use proto::quilkin::extensions::filters::token_router::v1alpha1::TokenRouter as ProtoConfig;
use std::convert::TryFrom;
use std::sync::Arc;

mod metrics;
mod proto;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(default)]
struct Config {
    /// the key to use when retrieving the token from the Filter's dynamic metadata
    #[serde(rename = "metadataKey", default = "default_metadata_key")]
    metadata_key: String,
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

/// Filter that only allows packets to be passed to Endpoints that have a matching
/// connection_id to the token stored in the Filter's dynamic metadata.
struct TokenRouter {
    log: Logger,
    metadata_key: Arc<String>,
    metrics: Metrics,
}

/// Factory for the TokenRouter filter
pub struct TokenRouterFactory {
    log: Logger,
}

impl TokenRouterFactory {
    pub fn new(base: &Logger) -> Self {
        TokenRouterFactory { log: base.clone() }
    }
}

impl FilterFactory for TokenRouterFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.token_router.v1alpha1.TokenRouter".into()
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Config = args
            .config
            .map(|config| config.deserialize::<Config, ProtoConfig>(self.name().as_str()))
            .transpose()?
            .unwrap_or_default();

        Ok(Box::new(TokenRouter::new(
            &self.log,
            config,
            Metrics::new(&args.metrics_registry)?,
        )))
    }
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

impl Filter for TokenRouter {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        match ctx.metadata.get(self.metadata_key.as_ref()) {
            None => {
                error!(self.log, "Filter configuration issue: token not found";
                    "metadata_key" => self.metadata_key.clone());
                self.metrics.packets_dropped_no_token_found.inc();
                None
            }
            Some(value) => match value.downcast_ref::<Vec<u8>>() {
                Some(token) => match ctx.endpoints.retain(|e| e.tokens.contains(token)) {
                    Ok(_) => Some(ctx.into()),
                    Err(_) => {
                        self.metrics.packets_dropped_no_endpoint_match.inc();
                        None
                    }
                },
                None => {
                    error!(self.log, "Filter configuration issue: retrieved token is not the correct type (Vec<u8>)";
                        "metadata_key" => self.metadata_key.clone());
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

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::ops::Deref;
    use std::sync::Arc;

    use prometheus::Registry;
    use serde_yaml::{Mapping, Value};

    use crate::config::Endpoints;
    use crate::test_utils::{assert_write_no_change, logger};

    use super::{
        default_metadata_key, Config, Metrics, ProtoConfig, TokenRouter, TokenRouterFactory,
    };
    use crate::cluster::Endpoint;
    use crate::extensions::filters::CAPTURED_BYTES;
    use crate::extensions::{CreateFilterArgs, Filter, FilterFactory, ReadContext};

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
        let endpoint1 = Endpoint::new(
            "127.0.0.1:80".parse().unwrap(),
            vec!["123".into()].into_iter().collect(),
            None,
        );
        let endpoint2 = Endpoint::new(
            "127.0.0.1:90".parse().unwrap(),
            vec!["456".into()].into_iter().collect(),
            None,
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
