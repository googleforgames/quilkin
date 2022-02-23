/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Filter for allowing/blocking traffic by IP and port.

use tracing::debug;

use crate::filters::firewall::metrics::Metrics;
use crate::filters::prelude::*;

use self::quilkin::filters::firewall::v1alpha1::Firewall as ProtoConfig;

crate::include_proto!("quilkin.filters.firewall.v1alpha1");

mod config;
mod metrics;

pub use config::{Action, Config, PortRange, PortRangeError, Rule};

pub const NAME: &str = "quilkin.filters.firewall.v1alpha1.Firewall";

pub fn factory() -> DynFilterFactory {
    Box::from(FirewallFactory::new())
}

struct FirewallFactory {}

impl FirewallFactory {
    pub fn new() -> Self {
        Self {}
    }
}

impl FilterFactory for FirewallFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn config_schema(&self) -> schemars::schema::RootSchema {
        schemars::schema_for!(Config)
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<FilterInstance, Error> {
        let (config_json, config) = self
            .require_config(args.config)?
            .deserialize::<Config, ProtoConfig>(self.name())?;

        let filter = Firewall::new(config, Metrics::new()?);
        Ok(FilterInstance::new(
            config_json,
            Box::new(filter) as Box<dyn Filter>,
        ))
    }
}

struct Firewall {
    metrics: Metrics,
    on_read: Vec<Rule>,
    on_write: Vec<Rule>,
}

impl Firewall {
    fn new(config: Config, metrics: Metrics) -> Self {
        Self {
            metrics,
            on_read: config.on_read,
            on_write: config.on_write,
        }
    }
}

impl Filter for Firewall {
    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn read(&self, ctx: ReadContext) -> Option<ReadResponse> {
        for rule in &self.on_read {
            if rule.contains(ctx.source.to_socket_addr().ok()?) {
                return match rule.action {
                    Action::Allow => {
                        debug!(
                            action = "Allow",
                            event = "read",
                            source = ?ctx.source.to_string()
                        );
                        self.metrics.packets_allowed_read.inc();
                        Some(ctx.into())
                    }
                    Action::Deny => {
                        debug!(action = "Deny", event = "read", source = ?ctx.source);
                        self.metrics.packets_denied_read.inc();
                        None
                    }
                };
            }
        }
        debug!(
            action = "default: Deny",
            event = "read",
            source = ?ctx.source.to_string()
        );
        self.metrics.packets_denied_read.inc();
        None
    }

    #[cfg_attr(feature = "instrument", tracing::instrument(skip(self, ctx)))]
    fn write(&self, ctx: WriteContext) -> Option<WriteResponse> {
        for rule in &self.on_write {
            if rule.contains(ctx.source.to_socket_addr().ok()?) {
                return match rule.action {
                    Action::Allow => {
                        debug!(
                            action = "Allow",
                            event = "write",
                            source = ?ctx.source.to_string()
                        );
                        self.metrics.packets_allowed_write.inc();
                        Some(ctx.into())
                    }
                    Action::Deny => {
                        debug!(action = "Deny", event = "write", source = ?ctx.source);
                        self.metrics.packets_denied_write.inc();
                        None
                    }
                };
            }
        }

        debug!(
            action = "default: Deny",
            event = "write",
            source = ?ctx.source.to_string()
        );
        self.metrics.packets_denied_write.inc();
        None
    }
}
#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::endpoint::{Endpoint, Endpoints, UpstreamEndpoints};
    use crate::filters::firewall::config::PortRange;
    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn read() {
        let firewall = Firewall {
            metrics: Metrics::new().unwrap(),
            on_read: vec![Rule {
                action: Action::Allow,
                source: "192.168.75.0/24".parse().unwrap(),
                ports: vec![PortRange::new(10, 100).unwrap()],
            }],
            on_write: vec![],
        };

        let local_ip = [192, 168, 75, 20];
        let ctx = ReadContext::new(
            UpstreamEndpoints::from(Endpoints::new(vec![Endpoint::new(
                (Ipv4Addr::LOCALHOST, 8080).into(),
            )])),
            (local_ip, 80).into(),
            vec![],
        );
        assert!(firewall.read(ctx).is_some());
        assert_eq!(1, firewall.metrics.packets_allowed_read.get());
        assert_eq!(0, firewall.metrics.packets_denied_read.get());

        let ctx = ReadContext::new(
            UpstreamEndpoints::from(Endpoints::new(vec![Endpoint::new(
                (Ipv4Addr::LOCALHOST, 8080).into(),
            )])),
            (local_ip, 2000).into(),
            vec![],
        );
        assert!(logs_contain("quilkin::filters::firewall")); // the given name to the the logger by tracing
        assert!(logs_contain("Allow"));

        assert!(firewall.read(ctx).is_none());
        assert_eq!(1, firewall.metrics.packets_allowed_read.get());
        assert_eq!(1, firewall.metrics.packets_denied_read.get());

        assert_eq!(0, firewall.metrics.packets_allowed_write.get());
        assert_eq!(0, firewall.metrics.packets_denied_write.get());
    }

    #[test]
    fn write() {
        let firewall = Firewall {
            metrics: Metrics::new().unwrap(),
            on_read: vec![],
            on_write: vec![Rule {
                action: Action::Allow,
                source: "192.168.75.0/24".parse().unwrap(),
                ports: vec![PortRange::new(10, 100).unwrap()],
            }],
        };

        let endpoint = Endpoint::new((Ipv4Addr::LOCALHOST, 80).into());
        let local_addr: crate::endpoint::EndpointAddress = (Ipv4Addr::LOCALHOST, 8081).into();

        let ctx = WriteContext::new(
            &endpoint,
            ([192, 168, 75, 20], 80).into(),
            local_addr.clone(),
            vec![],
        );
        assert!(firewall.write(ctx).is_some());
        assert_eq!(1, firewall.metrics.packets_allowed_write.get());
        assert_eq!(0, firewall.metrics.packets_denied_write.get());

        let ctx = WriteContext::new(
            &endpoint,
            ([192, 168, 77, 20], 80).into(),
            local_addr,
            vec![],
        );
        assert!(firewall.write(ctx).is_none());
        assert_eq!(1, firewall.metrics.packets_allowed_write.get());
        assert_eq!(1, firewall.metrics.packets_denied_write.get());

        assert_eq!(0, firewall.metrics.packets_allowed_read.get());
        assert_eq!(0, firewall.metrics.packets_denied_read.get());
    }
}
