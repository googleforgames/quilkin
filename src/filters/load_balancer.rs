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

mod config;
mod endpoint_chooser;

use crate::filters::{prelude::*, DynFilterFactory};

use config::ProtoConfig;
use endpoint_chooser::EndpointChooser;

pub use config::{Config, Policy};

pub const NAME: &str = "quilkin.extensions.filters.load_balancer.v1alpha1.LoadBalancer";

/// Returns a factory for creating load balancing filters.
pub fn factory() -> DynFilterFactory {
    Box::from(LoadBalancerFilterFactory)
}

/// Balances packets over the upstream endpoints.
struct LoadBalancer {
    endpoint_chooser: Box<dyn EndpointChooser>,
}

impl Filter for LoadBalancer {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        self.endpoint_chooser.choose_endpoints(&mut ctx.endpoints);
        Some(ctx.into())
    }
}

struct LoadBalancerFilterFactory;

impl FilterFactory for LoadBalancerFilterFactory {
    fn name(&self) -> &'static str {
        NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Config = self
            .require_config(args.config)?
            .deserialize::<Config, ProtoConfig>(self.name())?;

        Ok(Box::new(LoadBalancer {
            endpoint_chooser: config.policy.as_endpoint_chooser(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;

    use crate::{
        endpoint::{Endpoint, Endpoints},
        filters::{
            load_balancer::LoadBalancerFilterFactory, CreateFilterArgs, Filter, FilterFactory,
            ReadContext,
        },
    };
    use prometheus::Registry;

    fn create_filter(config: &str) -> Box<dyn Filter> {
        let factory = LoadBalancerFilterFactory;
        factory
            .create_filter(CreateFilterArgs::fixed(
                Registry::default(),
                Some(&serde_yaml::from_str(config).unwrap()),
            ))
            .unwrap()
    }

    fn get_response_addresses(
        filter: &dyn Filter,
        input_addresses: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        filter
            .read(ReadContext::new(
                Endpoints::new(
                    input_addresses
                        .iter()
                        .map(|addr| Endpoint::new(*addr))
                        .collect(),
                )
                .unwrap()
                .into(),
                "127.0.0.1:8080".parse().unwrap(),
                vec![],
            ))
            .unwrap()
            .endpoints
            .iter()
            .map(|ep| ep.address)
            .collect::<Vec<_>>()
    }

    #[test]
    fn round_robin_load_balancer_policy() {
        let addresses = vec![
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.2:8080".parse().unwrap(),
            "127.0.0.3:8080".parse().unwrap(),
        ];

        let yaml = "
policy: ROUND_ROBIN
";
        let filter = create_filter(yaml);

        // Check that we repeat the same addresses in sequence forever.
        let expected_sequence = addresses.iter().map(|addr| vec![*addr]).collect::<Vec<_>>();

        for _ in 0..10 {
            assert_eq!(
                expected_sequence,
                (0..addresses.len())
                    .map(|_| get_response_addresses(filter.as_ref(), &addresses))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn random_load_balancer_policy() {
        let addresses = vec![
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.2:8080".parse().unwrap(),
            "127.0.0.3:8080".parse().unwrap(),
        ];

        let yaml = "
policy: RANDOM
";
        let filter = create_filter(yaml);

        // Run a few selection rounds through the addresses.
        let mut result_sequences = vec![];
        for _ in 0..10 {
            let sequence = (0..addresses.len())
                .map(|_| get_response_addresses(filter.as_ref(), &addresses))
                .collect::<Vec<_>>();
            result_sequences.push(sequence);
        }

        // Check that every address was chosen at least once.
        assert_eq!(
            addresses.into_iter().collect::<HashSet<_>>(),
            result_sequences
                .clone()
                .into_iter()
                .flatten()
                .flatten()
                .collect::<HashSet<_>>(),
        );

        // Check that there is at least one different sequence of addresses.
        assert!(
            &result_sequences[1..]
                .iter()
                .any(|seq| seq != &result_sequences[0]),
            "the same sequence of addresses were chosen for random load balancer"
        );
    }
}
