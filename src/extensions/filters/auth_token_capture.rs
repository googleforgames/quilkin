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

use std::cmp;

use serde::{Deserialize, Serialize};

use crate::extensions::filters::AUTHENTICATION_TOKEN_KEY;
use crate::extensions::{
    CreateFilterArgs, DownstreamContext, DownstreamResponse, Error, Filter, FilterFactory,
    UpstreamContext, UpstreamResponse,
};

#[derive(Serialize, Deserialize, Debug)]
/// Strategy to apply for acquiring the auth token in the UDP packet
enum Strategy {
    #[serde(rename = "BEGINNING")]
    /// Looks for the token at the beginning of the packet
    Beginning,
    #[serde(rename = "END")]
    /// Look for the token at the end of the packet
    End,
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    #[serde(default)]
    strategy: Strategy,
    /// the number of bytes that the auth token is
    #[serde(rename = "byteCount")]
    byte_count: usize,
    /// whether or not to remove the token from the packet
    #[serde(default)]
    remove: bool,
}

impl Default for Strategy {
    fn default() -> Self {
        Strategy::End
    }
}

pub struct AuthTokenCaptureFactory;

impl Default for AuthTokenCaptureFactory {
    fn default() -> Self {
        Self {}
    }
}

impl FilterFactory for AuthTokenCaptureFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.auth_token_capture.v1alpha1.AuthTokenCapture".into()
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Config = serde_yaml::to_string(&args.config)
            .and_then(|raw_config| serde_yaml::from_str(raw_config.as_str()))
            .map_err(|err| Error::DeserializeFailed(err.to_string()))?;

        Ok(Box::new(AuthTokenCapture::new(config)))
    }
}

struct AuthTokenCapture {
    capture: Box<dyn Capture + Sync + Send>,
    byte_count: usize,
    remove: bool,
}

impl AuthTokenCapture {
    fn new(config: Config) -> Self {
        let capture: Box<dyn Capture + Sync + Send> = match config.strategy {
            Strategy::Beginning => Box::new(Beginning {}),
            Strategy::End => Box::new(End {}),
        };

        AuthTokenCapture {
            capture,
            byte_count: config.byte_count,
            remove: config.remove,
        }
    }
}

impl Filter for AuthTokenCapture {
    fn on_downstream_receive(&self, mut ctx: DownstreamContext) -> Option<DownstreamResponse> {
        // if the byte count is bigger than the packet size, then just take the entire
        // packet as it currently exists.
        let byte_count = cmp::min(self.byte_count, ctx.contents.len());
        let token = self
            .capture
            .capture(&mut ctx.contents, byte_count, self.remove);

        ctx.values
            .insert(AUTHENTICATION_TOKEN_KEY.into(), Box::new(token));

        Some(ctx.into())
    }

    fn on_upstream_receive(&self, ctx: UpstreamContext) -> Option<UpstreamResponse> {
        Some(ctx.into())
    }
}

/// Trait to implement different strategies for capturing authentication tokens
trait Capture {
    /// capture the auth token form the contents. If remove is true, contents will be altered to
    /// not have the auth token anymore.
    /// Returns the auth token.
    fn capture(&self, contents: &mut Vec<u8>, byte_count: usize, remove: bool) -> Vec<u8>;
}

struct End;
impl Capture for End {
    fn capture(&self, contents: &mut Vec<u8>, byte_count: usize, remove: bool) -> Vec<u8> {
        if remove {
            return contents.split_off(contents.len() - byte_count);
        }

        contents
            .iter()
            .skip(contents.len() - byte_count)
            .cloned()
            .collect::<Vec<u8>>()
    }
}

struct Beginning;
impl Capture for Beginning {
    fn capture(&self, contents: &mut Vec<u8>, byte_count: usize, remove: bool) -> Vec<u8> {
        if remove {
            return contents.drain(..byte_count).collect();
        }

        contents.iter().cloned().take(byte_count).collect()
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
        let factory = AuthTokenCaptureFactory::default();
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let mut map = Mapping::new();
        map.insert(
            Value::String("strategy".into()),
            Value::String("END".into()),
        );
        map.insert(Value::String("byteCount".into()), Value::Number(3.into()));
        map.insert(Value::String("remove".into()), Value::Bool(true));

        let filter = factory
            .create_filter(CreateFilterArgs::new(
                &connection,
                Some(&Value::Mapping(map)),
            ))
            .unwrap();
        assert_end_strategy(filter.as_ref());
    }

    #[test]
    fn factory_invalid_config() {
        let factory = AuthTokenCaptureFactory::default();
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let mut map = Mapping::new();
        map.insert(
            Value::String("byte_count".into()),
            Value::String("WRONG".into()),
        );

        let result = factory.create_filter(CreateFilterArgs::new(
            &connection,
            Some(&Value::Mapping(map)),
        ));
        assert!(result.is_err(), "Should be an error");
    }

    #[test]
    fn on_downstream_receive() {
        let config = Config {
            strategy: Strategy::End,
            byte_count: 3,
            remove: true,
        };
        let filter = AuthTokenCapture::new(config);
        assert_end_strategy(&filter);
    }

    #[test]
    fn on_downstream_receive_overflow_byte_count() {
        let config = Config {
            strategy: Strategy::End,
            byte_count: 99,
            remove: true,
        };
        let filter = AuthTokenCapture::new(config);
        let endpoints = vec![EndPoint {
            name: "e1".to_string(),
            address: "127.0.0.1:81".parse().unwrap(),
            connection_ids: vec![],
        }];
        let response = filter
            .on_downstream_receive(DownstreamContext::new(
                endpoints,
                "127.0.0.1:80".parse().unwrap(),
                "abc".to_string().into_bytes(),
            ))
            .unwrap();

        assert_eq!(b"".to_vec(), response.contents);
        let token = response
            .values
            .get(AUTHENTICATION_TOKEN_KEY)
            .unwrap()
            .downcast_ref::<Vec<u8>>()
            .unwrap();
        assert_eq!(b"abc", token.as_slice());
    }

    #[test]
    fn on_upstream_receive() {
        let config = Config {
            strategy: Strategy::End,
            byte_count: 0,
            remove: false,
        };
        let filter = AuthTokenCapture::new(config);
        assert_filter_on_downstream_receive_no_change(&filter);
    }

    #[test]
    fn end_capture() {
        let end = End {};
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
        let beg = Beginning {};
        let mut contents = b"abchello".to_vec();

        let result = beg.capture(&mut contents, 3, false);
        assert_eq!(b"abc".to_vec(), result);
        assert_eq!(b"abchello".to_vec(), contents);

        let result = beg.capture(&mut contents, 3, true);
        assert_eq!(b"abc".to_vec(), result);
        assert_eq!(b"hello".to_vec(), contents);
    }

    fn assert_end_strategy<F>(filter: &F)
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
                endpoints,
                "127.0.0.1:80".parse().unwrap(),
                "helloabc".to_string().into_bytes(),
            ))
            .unwrap();

        assert_eq!(b"hello".to_vec(), response.contents);
        let token = response
            .values
            .get(AUTHENTICATION_TOKEN_KEY)
            .unwrap()
            .downcast_ref::<Vec<u8>>()
            .unwrap();
        assert_eq!(b"abc", token.as_slice());
    }
}
