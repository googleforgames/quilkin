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

use std::convert::TryFrom;
use std::sync::atomic::{AtomicUsize, Ordering};

use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::{config::UpstreamEndpoints, filters::prelude::*, map_proto_enum};

crate::include_proto!("quilkin.extensions.filters.load_balancer.v1alpha1");

use self::quilkin::extensions::filters::load_balancer::v1alpha1::{
    load_balancer::Policy as ProtoPolicy, LoadBalancer as ProtoConfig,
};

/// Policy represents how a [`LoadBalancerFilter`] distributes
/// packets across endpoints.
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum Policy {
    /// Send packets to endpoints in turns.
    #[serde(rename = "ROUND_ROBIN")]
    RoundRobin,
    /// Send packets to endpoints chosen at random.
    #[serde(rename = "RANDOM")]
    Random,
}

impl Default for Policy {
    fn default() -> Self {
        Policy::RoundRobin
    }
}

/// Config represents configuration for a [`LoadBalancerFilter`].
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct Config {
    #[serde(default)]
    policy: Policy,
}
impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> Result<Self, Self::Error> {
        let policy = p
            .policy
            .map(|policy| {
                map_proto_enum!(
                    value = policy.value,
                    field = "policy",
                    proto_enum_type = ProtoPolicy,
                    target_enum_type = Policy,
                    variants = [RoundRobin, Random]
                )
            })
            .transpose()?
            .unwrap_or_else(Policy::default);
        Ok(Self { policy })
    }
}

/// EndpointChooser chooses from a set of endpoints that a proxy is connected to.
trait EndpointChooser: Send + Sync {
    /// choose_endpoints asks for the next endpoint(s) to use.
    fn choose_endpoints(&self, endpoints: &mut UpstreamEndpoints);
}

/// RoundRobinEndpointChooser chooses endpoints in round-robin order.
pub struct RoundRobinEndpointChooser {
    next_endpoint: AtomicUsize,
}

impl RoundRobinEndpointChooser {
    fn new() -> Self {
        RoundRobinEndpointChooser {
            next_endpoint: AtomicUsize::new(0),
        }
    }
}

impl EndpointChooser for RoundRobinEndpointChooser {
    fn choose_endpoints(&self, endpoints: &mut UpstreamEndpoints) {
        let count = self.next_endpoint.fetch_add(1, Ordering::Relaxed);
        // Note: Unwrap is safe here because the index is guaranteed to be in range.
        let num_endpoints = endpoints.size();
        endpoints.keep(count % num_endpoints)
            .expect("BUG: unwrap should have been safe because index into endpoints list should be in range");
    }
}

/// RandomEndpointChooser chooses endpoints in random order.
pub struct RandomEndpointChooser;

impl EndpointChooser for RandomEndpointChooser {
    fn choose_endpoints(&self, endpoints: &mut UpstreamEndpoints) {
        // Note: Unwrap is safe here because the index is guaranteed to be in range.
        let idx = (&mut thread_rng()).gen_range(0..endpoints.size());
        endpoints.keep(idx)
            .expect("BUG: unwrap should have been safe because index into endpoints list should be in range");
    }
}

/// Creates instances of LoadBalancerFilter.
#[derive(Default)]
pub struct LoadBalancerFilterFactory;

/// LoadBalancerFilter load balances packets over the upstream endpoints.
#[crate::filter("quilkin.extensions.filters.load_balancer.v1alpha1.LoadBalancer")]
struct LoadBalancerFilter {
    endpoint_chooser: Box<dyn EndpointChooser>,
}

impl FilterFactory for LoadBalancerFilterFactory {
    fn name(&self) -> &'static str {
        LoadBalancerFilter::FILTER_NAME
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Config = self
            .require_config(args.config)?
            .deserialize::<Config, ProtoConfig>(self.name())?;

        let endpoint_chooser: Box<dyn EndpointChooser> = match config.policy {
            Policy::RoundRobin => Box::new(RoundRobinEndpointChooser::new()),
            Policy::Random => Box::new(RandomEndpointChooser),
        };

        Ok(Box::new(LoadBalancerFilter { endpoint_chooser }))
    }
}

impl Filter for LoadBalancerFilter {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        self.endpoint_chooser.choose_endpoints(&mut ctx.endpoints);
        Some(ctx.into())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::convert::TryFrom;
    use std::net::SocketAddr;

    use super::quilkin::extensions::filters::load_balancer::v1alpha1::{
        load_balancer::{Policy as ProtoPolicy, PolicyValue},
        LoadBalancer as ProtoConfig,
    };
    use super::{Config, Policy};
    use crate::cluster::Endpoint;
    use crate::config::Endpoints;
    use crate::filters::{
        extensions::load_balancer::LoadBalancerFilterFactory, CreateFilterArgs, Filter,
        FilterFactory, ReadContext,
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
    fn convert_proto_config() {
        let test_cases = vec![
            (
                "RandomPolicy",
                ProtoConfig {
                    policy: Some(PolicyValue {
                        value: ProtoPolicy::Random as i32,
                    }),
                },
                Some(Config {
                    policy: Policy::Random,
                }),
            ),
            (
                "RoundRobinPolicy",
                ProtoConfig {
                    policy: Some(PolicyValue {
                        value: ProtoPolicy::RoundRobin as i32,
                    }),
                },
                Some(Config {
                    policy: Policy::RoundRobin,
                }),
            ),
            (
                "should fail when invalid policy is provided",
                ProtoConfig {
                    policy: Some(PolicyValue { value: 42 }),
                },
                None,
            ),
            (
                "should use correct default values",
                ProtoConfig { policy: None },
                Some(Config {
                    policy: Policy::default(),
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
