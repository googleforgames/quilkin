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

use crate::config::EndPoint;
use crate::extensions::filter_registry::CreateFilterArgs;
use crate::extensions::{Error, Filter, FilterFactory};
use metrics::Metrics;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot::{channel, Sender};
use tokio::time::{self, Instant};

mod metrics;

/// RateLimitFilter applies rate limiting to packets flowing through the proxy
///
/// # Configuration
///
/// ```yaml
/// local:
///   port: 7000 # the port to receive traffic to locally
/// filters:
///   - name: quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit
///     config:
///       max_packets: 10
///       period: 500ms
/// client:
///   addresses:
///     - 127.0.0.1:7001
///   connection_id: 1x7ijy6
/// ```
///  `config.max_packets` is the maximum number of packets allowed
///  to be forwarded by the rate limiter in a given duration.
///  `config.period` (optional) is the duration during which config.max_packets applies.
///  If none is provided, it defaults to 1 second.
///
/// # Metrics
///
/// `filter_LocalRateLimit.packets_dropped`: Total number of packets dropped due to rate limiting
///

/// Config represents a RateLimitFilter's configuration.
#[derive(Serialize, Deserialize, Debug)]
struct Config {
    /// max_packets is the maximum number of packets allowed
    /// to be forwarded by the rate limiter in a given duration.
    max_packets: usize,
    /// period is the duration during which max_packets applies.
    /// If none is provided, it defaults to 1 second.
    #[serde(with = "humantime_serde")]
    period: Option<Duration>,
}

/// Creates instances of RateLimitFilter.
#[derive(Default)]
pub struct RateLimitFilterFactory;

/// A filter that implements rate limiting on packets based on
/// the token-bucket algorithm.
/// Packets that violate the rate limit are dropped.
/// It only applies rate limiting on packets that are destined for the
/// proxy's endpoints. All other packets flow through the filter untouched.
struct RateLimitFilter {
    /// available_tokens is how many tokens are left in the bucket any
    /// any given moment.
    available_tokens: Arc<AtomicUsize>,
    /// metrics reporter for this filter.
    metrics: Metrics,
    /// shutdown_tx signals the spawned token refill future to exit.
    shutdown_tx: Option<Sender<()>>,
}

impl FilterFactory for RateLimitFilterFactory {
    fn name(&self) -> String {
        "quilkin.extensions.filters.local_rate_limit.v1alpha1.LocalRateLimit".into()
    }

    fn create_filter(&self, args: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        let config: Config = serde_yaml::to_string(args.config)
            .and_then(|raw_config| serde_yaml::from_str(raw_config.as_str()))
            .map_err(|err| Error::DeserializeFailed(err.to_string()))?;

        match config.period {
            Some(period) if period.lt(&Duration::from_millis(100)) => Err(Error::FieldInvalid {
                field: "period".into(),
                reason: "value must be at least 100ms".into(),
            }),
            _ => Ok(Box::new(RateLimitFilter::new(
                config,
                Metrics::new(&args.metrics_registry)?,
            ))),
        }
    }
}

impl RateLimitFilter {
    /// new returns a new RateLimitFilter. It spawns a future in the background
    /// that periodically refills the rate limiter's tokens.
    fn new(config: Config, metrics: Metrics) -> Self {
        let (shutdown_tx, mut shutdown_rx) = channel();

        let tokens = Arc::new(AtomicUsize::new(config.max_packets));

        let max_tokens = config.max_packets;
        let period = config.period.unwrap_or(Duration::from_secs(1));
        let available_tokens = tokens.clone();
        let _ = tokio::spawn(async move {
            let mut interval = time::interval_at(Instant::now() + period, period);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Refill tokens.
                        let mut refilled = false;
                        while !refilled {
                            let remaining_tokens = available_tokens.load(Ordering::Relaxed);

                            refilled = available_tokens.compare_and_swap(
                                remaining_tokens,
                                max_tokens,
                                Ordering::Relaxed) == remaining_tokens;
                        }
                    },
                    _ = &mut shutdown_rx => {
                        return;
                    }
                }
            }
        });

        RateLimitFilter {
            available_tokens: tokens,
            metrics,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    /// acquire_token is called on behalf of every packet that is eligible
    /// for rate limiting. It returns whether there exists a token in the current
    /// period - determining whether or not the packet should be forwarded or dropped.
    fn acquire_token(&self) -> Option<()> {
        loop {
            let remaining_tokens = self.available_tokens.load(Ordering::Relaxed);

            if remaining_tokens == 0 {
                return None;
            }

            if self.available_tokens.compare_and_swap(
                remaining_tokens,
                remaining_tokens - 1,
                Ordering::Relaxed,
            ) == remaining_tokens
            {
                return Some(());
            }
        }
    }
}

impl Drop for RateLimitFilter {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            shutdown_tx.send(()).ok();
        }
    }
}

impl Filter for RateLimitFilter {
    fn on_downstream_receive(
        &self,
        endpoints: &[EndPoint],
        _from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
        self.acquire_token()
            .map(|()| (endpoints.to_vec(), contents))
            .or_else(|| {
                self.metrics.packets_dropped_total.inc();
                None
            })
    }

    fn on_upstream_receive(
        &self,
        _endpoint: &EndPoint,
        _from: SocketAddr,
        _to: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        Some(contents)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::EndPoint;
    use crate::extensions::filters::local_rate_limit::metrics::Metrics;
    use crate::extensions::filters::local_rate_limit::{Config, RateLimitFilter};
    use crate::extensions::Filter;
    use prometheus::Registry;
    use std::time::Duration;
    use tokio::time;

    fn rate_limiter(config: Config) -> RateLimitFilter {
        RateLimitFilter::new(config, Metrics::new(&Registry::default()).unwrap())
    }

    #[tokio::test]
    async fn initially_available_tokens() {
        // Test that we always start with the max number of tokens available.
        let r = rate_limiter(Config {
            max_packets: 3,
            period: Some(Duration::from_millis(100)),
        });

        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), None);
    }

    #[tokio::test]
    async fn token_exhaustion_and_refill() {
        let r = rate_limiter(Config {
            max_packets: 2,
            period: Some(Duration::from_millis(100)),
        });

        // Exhaust tokens
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), None);

        // Wait for refill
        time::delay_for(Duration::from_millis(110)).await;

        // Exhaust tokens again.
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), None);
    }

    #[tokio::test]
    async fn token_refill_maximum() {
        // Test that we never refill more than the max_tokens specified.

        let r = rate_limiter(Config {
            max_packets: 3,
            period: Some(Duration::from_millis(100)),
        });

        // Use up some of the tokens.
        assert_eq!(r.acquire_token(), Some(()));

        // Wait for refill
        time::delay_for(Duration::from_millis(110)).await;

        // Refill should not go over max token limit.
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), Some(()));
        assert_eq!(r.acquire_token(), None);
    }

    #[tokio::test]
    async fn filter_with_no_available_tokens() {
        let r = rate_limiter(Config {
            max_packets: 0,
            period: Some(Duration::from_millis(100)),
        });

        // Check that other routes are not affected.
        assert_eq!(
            r.on_upstream_receive(
                &EndPoint::new("e".to_string(), "127.0.0.1:8081".parse().unwrap(), vec![]),
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8080".parse().unwrap(),
                vec![9]
            ),
            Some(vec![9])
        );

        // Check that we're rate limited.
        assert_eq!(
            r.on_downstream_receive(&vec![], "127.0.0.1:8080".parse().unwrap(), vec![9]),
            None
        );
    }

    #[tokio::test]
    async fn filter_with_available_tokens() {
        let r = rate_limiter(Config {
            max_packets: 1,
            period: Some(Duration::from_millis(100)),
        });

        assert_eq!(
            r.on_downstream_receive(&vec![], "127.0.0.1:8080".parse().unwrap(), vec![9]),
            Some((vec![], vec![9]))
        );
        // We should be out of tokens now.
        assert_eq!(None, r.acquire_token());

        // Check that other routes are not affected.
        assert_eq!(
            r.on_upstream_receive(
                &EndPoint::new("e".to_string(), "127.0.0.1:8081".parse().unwrap(), vec![]),
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8080".parse().unwrap(),
                vec![9]
            ),
            Some(vec![9])
        );
    }
}
