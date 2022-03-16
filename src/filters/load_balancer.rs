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

pub const NAME: &str = "quilkin.filters.load_balancer.v1alpha1.LoadBalancer";

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
        self.endpoint_chooser.choose_endpoints(&mut ctx);
        Some(ctx.into())
    }
}

struct LoadBalancerFilterFactory;

impl FilterFactory for LoadBalancerFilterFactory {
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
        let filter = LoadBalancer {
            endpoint_chooser: config.policy.as_endpoint_chooser(),
        };
        Ok(FilterInstance::new(
            config_json,
            Box::new(filter) as Box<dyn Filter>,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::Ipv4Addr};

    use crate::{
        endpoint::{Endpoint, EndpointAddress, Endpoints},
        filters::{
            load_balancer::LoadBalancerFilterFactory, CreateFilterArgs, Filter, FilterFactory,
            ReadContext,
        },
    };

    fn create_filter(config: &str) -> Box<dyn Filter> {
        let factory = LoadBalancerFilterFactory;
        factory
            .create_filter(CreateFilterArgs::fixed(Some(
                serde_yaml::from_str(config).unwrap(),
            )))
            .unwrap()
            .filter
    }

    fn get_response_addresses(
        filter: &dyn Filter,
        input_addresses: &[EndpointAddress],
        source: EndpointAddress,
    ) -> Vec<EndpointAddress> {
        filter
            .read(ReadContext::new(
                Endpoints::new(input_addresses.iter().cloned().map(Endpoint::new).collect()).into(),
                source,
                vec![],
            ))
            .unwrap()
            .endpoints
            .iter()
            .map(|ep| ep.address.clone())
            .collect::<Vec<_>>()
    }

    #[test]
    fn round_robin_load_balancer_policy() {
        let addresses: Vec<EndpointAddress> = vec![
            ([127, 0, 0, 1], 8080).into(),
            ([127, 0, 0, 2], 8080).into(),
            ([127, 0, 0, 3], 8080).into(),
        ];

        let yaml = "policy: ROUND_ROBIN";
        let filter = create_filter(yaml);

        // Check that we repeat the same addresses in sequence forever.
        let expected_sequence = addresses
            .iter()
            .map(|addr| vec![addr.clone()])
            .collect::<Vec<_>>();

        for _ in 0..10 {
            assert_eq!(
                expected_sequence,
                (0..addresses.len())
                    .map(|_| get_response_addresses(
                        filter.as_ref(),
                        &addresses,
                        "127.0.0.1:8080".parse().unwrap()
                    ))
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
                .map(|_| {
                    get_response_addresses(
                        filter.as_ref(),
                        &addresses,
                        "127.0.0.1:8080".parse().unwrap(),
                    )
                })
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

    #[test]
    fn hash_load_balancer_policy() {
        let addresses: Vec<EndpointAddress> = vec![
            ([127, 0, 0, 1], 8080).into(),
            ([127, 0, 0, 2], 8080).into(),
            ([127, 0, 0, 3], 8080).into(),
        ];
        let source_ips = vec![[127u8, 1, 1, 1], [127, 2, 2, 2], [127, 3, 3, 3]];
        let source_ports = vec![11111u16, 22222, 33333, 44444, 55555];

        let yaml = "
policy: HASH
";
        let filter = create_filter(yaml);

        // Run a few selection rounds through the addresses.
        let mut result_sequences = vec![];
        for _ in 0..10 {
            let sequence = (0..addresses.len())
                .map(|_| {
                    get_response_addresses(
                        filter.as_ref(),
                        &addresses,
                        (Ipv4Addr::LOCALHOST, 8080).into(),
                    )
                })
                .collect::<Vec<_>>();
            result_sequences.push(sequence);
        }

        // Verify that all packets went the same way
        assert_eq!(
            1,
            result_sequences
                .into_iter()
                .flatten()
                .flatten()
                .collect::<HashSet<_>>()
                .len(),
        );

        // Run a few selection rounds through the address
        // this time vary the port for a single IP
        let mut result_sequences = vec![];
        for port in source_ports.iter().copied() {
            let sequence = (0..addresses.len())
                .map(|_| {
                    get_response_addresses(
                        filter.as_ref(),
                        &addresses,
                        (Ipv4Addr::LOCALHOST, port).into(),
                    )
                })
                .collect::<Vec<_>>();
            result_sequences.push(sequence);
        }

        // Verify that more than 1 path was picked
        assert_ne!(
            1,
            result_sequences
                .into_iter()
                .flatten()
                .flatten()
                .collect::<HashSet<_>>()
                .len(),
        );

        // Run a few selection rounds through the addresses
        // This time vary the source IP and port
        let mut result_sequences = vec![];
        for ip in source_ips {
            for port in source_ports.iter().copied() {
                let sequence = (0..addresses.len())
                    .map(|_| get_response_addresses(filter.as_ref(), &addresses, (ip, port).into()))
                    .collect::<Vec<_>>();
                result_sequences.push(sequence);
            }
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
            "the same sequence of addresses were chosen for hash load balancer"
        );
    }
}
