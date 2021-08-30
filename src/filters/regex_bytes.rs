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

mod config;
mod metrics;
mod proto;

use std::sync::Arc;

use slog::{o, warn, Logger};

use crate::filters::prelude::*;

use metrics::Metrics;
use proto::quilkin::extensions::filters::regex_bytes::v1alpha1::RegexBytes as ProtoConfig;
use regex::bytes::Regex;

pub use config::Config;

pub const NAME: &str = "quilkin.extensions.filters.regex_bytes.v1alpha1.RegexBytes";

/// Creates a new factory for generating capture filters.
pub fn factory(base: &Logger) -> DynFilterFactory {
    Box::from(RegexBytesFactory::new(base))
}

struct RegexBytes {
    log: Logger,
    //capture: Box<dyn Capture + Sync + Send>,
    /// metrics reporter for this filter.
    metrics: Metrics,
    regex_expression: Arc<String>,
    metadata_key: Arc<String>,
}

impl RegexBytes {
    fn new(base: &Logger, config: Config, metrics: Metrics) -> Self {
        RegexBytes {
            log: base.new(o!("source" => "extensions::RegexBytes")),
            //capture: config.strategy.as_capture(),
            metrics,
            regex_expression: Arc::new(config.regex_expression),
            metadata_key: Arc::new(config.metadata_key),
        }
    }
}

impl Filter for RegexBytes {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}$").unwrap();

        if !re.is_match(&ctx.contents) {
            // on error -> drop
            self.metrics.packets_matched_total.inc();

            return None;
        }

        // on success -> pass | capture

        Some(ctx.into())
    }
}

struct RegexBytesFactory {
    log: Logger,
}

impl RegexBytesFactory {
    pub fn new(base: &Logger) -> Self {
        RegexBytesFactory { log: base.clone() }
    }
}

impl FilterFactory for RegexBytesFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(RegexBytes::new(
            &self.log,
            self.require_config(args.config)?
                .deserialize::<Config, ProtoConfig>(self.name())?,
            Metrics::new(&args.metrics_registry)?,
        )))
    }
}
