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

use crate::extensions::filters::endpoint_authentication::metrics::Metrics;
use crate::extensions::filters::CAPTURED_BYTES;
use crate::extensions::{
    CreateFilterArgs, DownstreamContext, DownstreamResponse, Error, Filter, FilterFactory,
    UpstreamContext, UpstreamResponse,
};

mod metrics;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    /// the key to use when retrieving the captured bytes in the filter context
    #[serde(rename = "metadataKey")]
    #[serde(default = "default_metadata_key")]
    metadata_key: String,
}

/// default value for the context key in the Config
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

struct EndpointAuthentication {
    log: Logger,
    values_key: String,
    metrics: Metrics,
}

/// Factory for the EndpointAuthentication filter that only allows packets to be passed to Endpoints that have a matching
/// connection_id to the token stored in the Filter's dynamic metadata.
pub struct EndpointAuthenticationFactory {
    log: Logger,
}

impl EndpointAuthenticationFactory {
    pub fn new(base: &Logger) -> Self {
        EndpointAuthenticationFactory { log: base.clone() }
    }
}

impl FilterFactory for EndpointAuthenticationFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.endpoint_authentication.v1alpha1.EndpointAuthentication".into()
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Option<Config> = serde_yaml::to_string(&args.config)
            .and_then(|raw_config| serde_yaml::from_str(raw_config.as_str()))
            .map_err(|err| Error::DeserializeFailed(err.to_string()))?;

        Ok(Box::new(EndpointAuthentication::new(
            &self.log,
            config.unwrap_or_default(),
            Metrics::new(&args.metrics_registry)?,
        )))
    }
}

impl EndpointAuthentication {
    fn new(base: &Logger, config: Config, metrics: Metrics) -> Self {
        Self {
            log: base.new(o!("source" => "extensions::EndpointAuthentication")),
            values_key: config.metadata_key,
            metrics,
        }
    }
}

impl Filter for EndpointAuthentication {
    fn on_downstream_receive(&self, mut ctx: DownstreamContext) -> Option<DownstreamResponse> {
        match ctx.metadata.get(self.values_key.as_str()) {
            None => {
                error!(self.log, "Value key not found in DownstreamContext"; "key" => self.values_key.clone());
                self.metrics.packets_dropped_total.inc();
                None
            }
            Some(value) => match value.downcast_ref::<Vec<u8>>() {
                Some(connection_id) => {
                    ctx.endpoints
                        .retain(|e| e.connection_ids.iter().any(|id| id == connection_id));
                    if ctx.endpoints.is_empty() {
                        self.metrics.packets_dropped_total.inc();
                        return None;
                    }
                    Some(ctx.into())
                }
                None => {
                    error!(self.log, "Type of value stored in DownstreamContext.values is not Vec<u8>";
                        "key" => self.values_key.clone());
                    self.metrics.packets_dropped_total.inc();
                    None
                }
            },
        }
    }
    fn on_upstream_receive(&self, ctx: UpstreamContext) -> Option<UpstreamResponse> {
        Some(ctx.into())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    use prometheus::Registry;
    use serde_yaml::{Mapping, Value};

    use crate::config::{ConnectionConfig, ConnectionId, EndPoint};
    use crate::test_utils::{assert_filter_on_upstream_receive_no_change, logger};

    use super::*;

    const TOKEN_KEY: &str = "TOKEN";

    fn router(config: Config) -> EndpointAuthentication {
        EndpointAuthentication::new(
            &logger(),
            config,
            Metrics::new(&Registry::default()).unwrap(),
        )
    }

    #[test]
    fn factory_custom_tokens() {
        let factory = EndpointAuthenticationFactory::new(&logger());
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let mut map = Mapping::new();
        map.insert(
            Value::String("metadataKey".into()),
            Value::String(TOKEN_KEY.into()),
        );

        let filter = factory
            .create_filter(CreateFilterArgs::new(
                &connection,
                Some(&Value::Mapping(map)),
            ))
            .unwrap();
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(TOKEN_KEY.into(), Box::new(b"123".to_vec()));
        assert_on_downstream_receive(filter.deref(), ctx);
    }

    #[test]
    fn factory_empty_config() {
        let factory = EndpointAuthenticationFactory::new(&logger());
        let connection = ConnectionConfig::Server { endpoints: vec![] };
        let map = Mapping::new();

        let filter = factory
            .create_filter(CreateFilterArgs::new(
                &connection,
                Some(&Value::Mapping(map)),
            ))
            .unwrap();
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(CAPTURED_BYTES.into(), Box::new(b"123".to_vec()));
        assert_on_downstream_receive(filter.deref(), ctx);
    }

    #[test]
    fn factory_no_config() {
        let factory = EndpointAuthenticationFactory::new(&logger());
        let connection = ConnectionConfig::Server { endpoints: vec![] };

        let filter = factory
            .create_filter(CreateFilterArgs::new(&connection, None))
            .unwrap();
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(CAPTURED_BYTES.into(), Box::new(b"123".to_vec()));
        assert_on_downstream_receive(filter.deref(), ctx);
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
            .insert(CAPTURED_BYTES.into(), Box::new(b"123".to_vec()));
        assert_on_downstream_receive(&filter, ctx);

        // invalid key
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(CAPTURED_BYTES.into(), Box::new(b"567".to_vec()));
        assert!(filter.on_downstream_receive(ctx).is_none());
        assert_eq!(1, filter.metrics.packets_dropped_total.get());

        // no key
        let ctx = new_ctx();
        assert!(filter.on_downstream_receive(ctx).is_none());
        assert_eq!(2, filter.metrics.packets_dropped_total.get());

        // wrong type key
        let mut ctx = new_ctx();
        ctx.metadata
            .insert(CAPTURED_BYTES.into(), Box::new(String::from("wrong")));
        assert!(filter.on_downstream_receive(ctx).is_none());
        assert_eq!(3, filter.metrics.packets_dropped_total.get());
    }

    #[test]
    fn on_upstream_receive() {
        let config = Config {
            metadata_key: CAPTURED_BYTES.into(),
        };
        let filter = router(config);
        assert_filter_on_upstream_receive_no_change(&filter);
    }

    fn new_ctx() -> DownstreamContext {
        let endpoint1 = EndPoint::new(
            "one".into(),
            "127.0.0.1:80".parse().unwrap(),
            vec![ConnectionId::from("123")],
        );
        let endpoint2 = EndPoint::new(
            "two".into(),
            "127.0.0.1:90".parse().unwrap(),
            vec![ConnectionId::from("456")],
        );

        DownstreamContext::new(
            vec![endpoint1, endpoint2],
            "127.0.0.1:100".parse().unwrap(),
            b"hello".to_vec(),
        )
    }

    fn assert_on_downstream_receive<F>(filter: &F, ctx: DownstreamContext)
    where
        F: Filter + ?Sized,
    {
        let result = filter.on_downstream_receive(ctx).unwrap();

        assert_eq!(b"hello".to_vec(), result.contents);
        assert_eq!(1, result.endpoints.len());
        assert_eq!("one", result.endpoints[0].name);
    }
}
