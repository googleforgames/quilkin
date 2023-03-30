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

crate::include_proto!("quilkin.filters.token_router.v1alpha1");

use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::{
    filters::{metadata::CAPTURED_BYTES, prelude::*},
    metadata,
};

use self::quilkin::filters::token_router::v1alpha1 as proto;

/// Filter that only allows packets to be passed to Endpoints that have a matching
/// connection_id to the token stored in the Filter's dynamic metadata.
pub struct TokenRouter {
    config: Config,
}

impl TokenRouter {
    fn new(config: Config) -> Self {
        Self { config }
    }
}

impl StaticFilter for TokenRouter {
    const NAME: &'static str = "quilkin.filters.token_router.v1alpha1.TokenRouter";
    type Configuration = Config;
    type BinaryConfiguration = proto::TokenRouter;

    fn try_from_config(config: Option<Self::Configuration>) -> Result<Self, CreationError> {
        Ok(TokenRouter::new(config.unwrap_or_default()))
    }
}

#[async_trait::async_trait]
impl Filter for TokenRouter {
    async fn read(&self, ctx: &mut ReadContext) -> Result<(), FilterError> {
        match ctx.metadata.get(&self.config.metadata_key) {
            Some(metadata::Value::Bytes(token)) => {
                ctx.endpoints.retain(|endpoint| {
                    if endpoint.metadata.known.tokens.contains(&**token) {
                        tracing::trace!(%endpoint.address, token = &*base64::encode(token), "Endpoint matched");
                        true
                    } else {
                        false
                    }
                });

                if ctx.endpoints.is_empty() {
                    Err(FilterError::new(Error::NoEndpointMatch(
                        self.config.metadata_key,
                        base64::encode(token),
                    )))
                } else {
                    Ok(())
                }
            }
            Some(value) => Err(FilterError::new(Error::InvalidType(
                self.config.metadata_key,
                value.clone(),
            ))),
            None => Err(FilterError::new(Error::NoTokenFound(
                self.config.metadata_key,
            ))),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no routing token found for `{0}`")]
    NoTokenFound(crate::metadata::Key),
    #[error("key `{0}` was found but wasn't bytes, found {1:?}")]
    InvalidType(crate::metadata::Key, crate::metadata::Value),
    #[error("no endpoint matched token `{1}` from `{0}`")]
    NoEndpointMatch(crate::metadata::Key, String),
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, schemars::JsonSchema)]
#[serde(default)]
pub struct Config {
    /// the key to use when retrieving the token from the Filter's dynamic metadata
    #[serde(rename = "metadataKey", default = "default_metadata_key")]
    pub metadata_key: metadata::Key,
}

/// Default value for [`Config::metadata_key`]
fn default_metadata_key() -> metadata::Key {
    metadata::Key::from_static(CAPTURED_BYTES)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            metadata_key: default_metadata_key(),
        }
    }
}

impl From<Config> for proto::TokenRouter {
    fn from(config: Config) -> Self {
        Self {
            metadata_key: Some(config.metadata_key.to_string()),
        }
    }
}

impl TryFrom<proto::TokenRouter> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: proto::TokenRouter) -> Result<Self, Self::Error> {
        Ok(Self {
            metadata_key: p
                .metadata_key
                .map(metadata::Key::new)
                .unwrap_or_else(default_metadata_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        endpoint::{Endpoint, Metadata},
        metadata::Value,
        test_utils::assert_write_no_change,
    };

    use super::*;

    const TOKEN_KEY: &str = "TOKEN";

    #[test]
    fn convert_proto_config() {
        let test_cases = vec![
            (
                "should succeed when all valid values are provided",
                proto::TokenRouter {
                    metadata_key: Some("foobar".into()),
                },
                Some(Config {
                    metadata_key: "foobar".into(),
                }),
            ),
            (
                "should use correct default values",
                proto::TokenRouter { metadata_key: None },
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

    #[tokio::test]
    async fn factory_custom_tokens() {
        let filter = TokenRouter::from_config(
            Config {
                metadata_key: TOKEN_KEY.into(),
            }
            .into(),
        );
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(TOKEN_KEY.into(), Value::Bytes(b"123".to_vec().into()));
        assert_read(&filter, ctx).await;
    }

    #[tokio::test]
    async fn factory_empty_config() {
        let filter = TokenRouter::from_config(None);
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(CAPTURED_BYTES.into(), Value::Bytes(b"123".to_vec().into()));
        assert_read(&filter, ctx).await;
    }

    #[tokio::test]
    async fn downstream_receive() {
        // valid key
        let config = Config {
            metadata_key: CAPTURED_BYTES.into(),
        };
        let filter = TokenRouter::from_config(config.into());

        let mut ctx = new_ctx();
        ctx.metadata
            .insert(CAPTURED_BYTES.into(), Value::Bytes(b"123".to_vec().into()));
        assert_read(&filter, ctx).await;

        // invalid key
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(CAPTURED_BYTES.into(), Value::Bytes(b"567".to_vec().into()));

        assert!(filter.read(&mut ctx).await.is_err());

        // no key
        let mut ctx = new_ctx();
        assert!(filter.read(&mut ctx).await.is_err());

        // wrong type key
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(CAPTURED_BYTES.into(), Value::String(String::from("wrong")));
        assert!(filter.read(&mut ctx).await.is_err());
    }

    #[tokio::test]
    async fn write() {
        let config = Config {
            metadata_key: CAPTURED_BYTES.into(),
        };
        let filter = TokenRouter::from_config(config.into());
        assert_write_no_change(&filter).await;
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
            vec![endpoint1, endpoint2],
            "127.0.0.1:100".parse().unwrap(),
            b"hello".to_vec(),
        )
    }

    async fn assert_read<F>(filter: &F, mut ctx: ReadContext)
    where
        F: Filter + ?Sized,
    {
        filter.read(&mut ctx).await.unwrap();

        assert_eq!(b"hello", &*ctx.contents);
    }
}
