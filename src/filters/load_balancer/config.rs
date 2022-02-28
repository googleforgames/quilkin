/*
 * Copyright 2021 Google LLC
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

crate::include_proto!("quilkin.filters.load_balancer.v1alpha1");

use std::convert::TryFrom;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use self::quilkin::filters::load_balancer::v1alpha1::load_balancer::Policy as ProtoPolicy;
use super::endpoint_chooser::{
    EndpointChooser, HashEndpointChooser, RandomEndpointChooser, RoundRobinEndpointChooser,
};
use crate::{filters::ConvertProtoConfigError, map_proto_enum};

pub use self::quilkin::filters::load_balancer::v1alpha1::LoadBalancer as ProtoConfig;

/// The configuration for [`load_balancer`][super].
#[derive(Serialize, Deserialize, Debug, PartialEq, JsonSchema)]
#[non_exhaustive]
pub struct Config {
    #[serde(default)]
    pub policy: Policy,
}

impl Config {
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }
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
                    variants = [RoundRobin, Random, Hash]
                )
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self { policy })
    }
}

/// Policy represents how a [`load_balancer`][super] distributes
/// packets across endpoints.
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, JsonSchema)]
pub enum Policy {
    /// Send packets to endpoints in turns.
    #[serde(rename = "ROUND_ROBIN")]
    RoundRobin,
    /// Send packets to endpoints chosen at random.
    #[serde(rename = "RANDOM")]
    Random,
    /// Send packets to endpoints based on hash of source IP and port.
    #[serde(rename = "HASH")]
    Hash,
}

impl Policy {
    pub fn as_endpoint_chooser(&self) -> Box<dyn EndpointChooser> {
        match self {
            Policy::RoundRobin => Box::new(RoundRobinEndpointChooser::new()),
            Policy::Random => Box::new(RandomEndpointChooser),
            Policy::Hash => Box::new(HashEndpointChooser),
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Policy::RoundRobin
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::{
        quilkin::filters::load_balancer::v1alpha1::load_balancer::{
            Policy as ProtoPolicy, PolicyValue,
        },
        Config, Policy, ProtoConfig,
    };

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
                "HashPolicy",
                ProtoConfig {
                    policy: Some(PolicyValue {
                        value: ProtoPolicy::Hash as i32,
                    }),
                },
                Some(Config {
                    policy: Policy::Hash,
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
}
