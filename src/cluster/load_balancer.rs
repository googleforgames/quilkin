use std::sync::atomic::{AtomicUsize, Ordering};

use rand::seq::SliceRandom;
use rand::thread_rng;

use crate::config::{ConnectionConfig, EndPoint, LoadBalancerPolicy};

// CLIENT_ENDPOINT_PREFIX is a prefix to the name of a client proxy's endpoint.
const CLIENT_ENDPOINT_PREFIX: &str = "address";

/// EndpointChooser chooses from a set of endpoints that a proxy is connected to.
trait EndpointChooser: Send + Sync {
    /// choose_endpoints asks for the next endpoint(s) to use.
    fn choose_endpoints(&self) -> Vec<EndPoint>;
}

/// LoadBalancer represents a load balancing algorithm over a set
/// of endpoints that a proxy is connected to.
pub struct LoadBalancer {
    endpoint_chooser: Box<dyn EndpointChooser>,
}

impl LoadBalancer {
    pub fn from_connection_config(connection_config: &ConnectionConfig) -> Self {
        let (policy_name, endpoints) = match connection_config {
            ConnectionConfig::Client {
                lb_policy,
                addresses,
                ..
            } => (
                lb_policy,
                addresses
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(offset, address)| EndPoint {
                        name: format!("{}-{}", CLIENT_ENDPOINT_PREFIX, offset),
                        address,
                        connection_ids: vec![],
                    })
                    .collect(),
            ),
            ConnectionConfig::Server { endpoints } => {
                (&Some(LoadBalancerPolicy::Broadcast), endpoints.clone())
            }
        };

        LoadBalancer::new(policy_name, endpoints)
    }

    pub fn new(policy_name: &Option<LoadBalancerPolicy>, endpoints: Vec<EndPoint>) -> Self {
        let endpoint_chooser: Box<dyn EndpointChooser> = match policy_name {
            Some(LoadBalancerPolicy::RoundRobin) => {
                Box::new(RoundRobinEndpointChooser::new(endpoints))
            }
            Some(LoadBalancerPolicy::Random) => Box::new(RandomEndpointChooser::new(endpoints)),
            Some(LoadBalancerPolicy::Broadcast) | None => {
                Box::new(BroadcastEndpointChooser::new(endpoints))
            }
        };

        LoadBalancer { endpoint_chooser }
    }

    // choose_endpoints returns a list of endpoints.
    pub fn choose_endpoints(&self) -> Vec<EndPoint> {
        self.endpoint_chooser.choose_endpoints()
    }
}

/// RoundRobinEndpointChooser chooses endpoints in round-robin order.
pub struct RoundRobinEndpointChooser {
    endpoints: Vec<EndPoint>,
    next_endpoint: AtomicUsize,
}

impl RoundRobinEndpointChooser {
    fn new(endpoints: Vec<EndPoint>) -> Self {
        RoundRobinEndpointChooser {
            endpoints,
            next_endpoint: AtomicUsize::new(0),
        }
    }
}

impl EndpointChooser for RoundRobinEndpointChooser {
    fn choose_endpoints(&self) -> Vec<EndPoint> {
        if self.endpoints.is_empty() {
            return vec![];
        }
        let offset = self.next_endpoint.fetch_add(1, Ordering::Relaxed);
        vec![self.endpoints[offset % self.endpoints.len()].clone()]
    }
}

/// RandomEndpointChooser chooses endpoints in random order.
pub struct RandomEndpointChooser {
    endpoints: Vec<EndPoint>,
}

impl RandomEndpointChooser {
    fn new(endpoints: Vec<EndPoint>) -> Self {
        RandomEndpointChooser { endpoints }
    }
}

impl EndpointChooser for RandomEndpointChooser {
    fn choose_endpoints(&self) -> Vec<EndPoint> {
        self.endpoints
            .choose(&mut thread_rng())
            .map(|e| vec![e.clone()])
            .unwrap_or_default()
    }
}

/// BroadcastEndpointChooser always chooses all endpoints.
pub struct BroadcastEndpointChooser {
    endpoints: Vec<EndPoint>,
}

impl BroadcastEndpointChooser {
    fn new(endpoints: Vec<EndPoint>) -> Self {
        BroadcastEndpointChooser { endpoints }
    }
}

impl EndpointChooser for BroadcastEndpointChooser {
    fn choose_endpoints(&self) -> Vec<EndPoint> {
        self.endpoints.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::LoadBalancer;
    use crate::config::ConnectionConfig;
    use crate::config::LoadBalancerPolicy::{Broadcast, Random, RoundRobin};

    #[test]
    fn round_robin_load_balancer_policy() {
        let addresses = vec![
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.2:8080".parse().unwrap(),
            "127.0.0.3:8080".parse().unwrap(),
        ];

        let lb = LoadBalancer::from_connection_config(&ConnectionConfig::Client {
            addresses: addresses.clone(),
            connection_id: "".into(),
            lb_policy: Some(RoundRobin),
        });

        // Check that we repeat the same addresses in sequence forever.
        let expected_sequence = addresses
            .clone()
            .iter()
            .map(|&a| vec![a])
            .collect::<Vec<_>>();
        for _ in 0..10 {
            assert_eq!(
                expected_sequence,
                (0..addresses.len())
                    .into_iter()
                    .map(|_| lb
                        .choose_endpoints()
                        .iter()
                        .map(|e| e.address)
                        .collect::<Vec<_>>())
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

        let lb = LoadBalancer::from_connection_config(&ConnectionConfig::Client {
            addresses: addresses.clone(),
            connection_id: "".into(),
            lb_policy: Some(Random),
        });

        // Run a few selection rounds through the addresses.
        let mut result_sequences = vec![];
        for _ in 0..10 {
            let sequence = (0..addresses.len())
                .into_iter()
                .map(|_| {
                    lb.choose_endpoints()
                        .iter()
                        .map(|e| e.address)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            result_sequences.push(sequence);
        }

        // Check that every address was chosen at least once.
        assert_eq!(
            addresses.clone().into_iter().collect::<HashSet<_>>(),
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
    fn broadcast_load_balancer_policy() {
        // Also tests that this is the default policy.
        for lb_policy in vec![None, Some(Broadcast)] {
            let addresses = vec![
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.2:8080".parse().unwrap(),
                "127.0.0.3:8080".parse().unwrap(),
            ];

            let lb = LoadBalancer::from_connection_config(&ConnectionConfig::Client {
                addresses: addresses.clone(),
                connection_id: "".into(),
                lb_policy,
            });

            // Check that we always return all addresses.
            for _ in 0..10 {
                assert_eq!(
                    addresses,
                    lb.choose_endpoints()
                        .iter()
                        .map(|e| e.address)
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}
