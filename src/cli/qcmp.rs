/*
 * Copyright 2023 Google LLC
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
use std::net::SocketAddr;

use crate::protocol::Protocol;

#[derive(Clone, Debug, clap::Subcommand)]
pub enum Qcmp {
    Ping(Ping),
}

/// Pings a endpoint for a `amount` of attempts, printing the resulting
/// median, average, and number of successful attempts.
#[derive(clap::Args, Clone, Debug)]
pub struct Ping {
    /// The quilkin endpoint to ping
    pub endpoint: SocketAddr,
    /// The number of pings to send to the endpoint (default: 5).
    #[clap(short, long, default_value_t = 5)]
    pub amount: usize,
}

impl Ping {
    pub async fn run(&self) -> crate::Result<()> {
        tracing::info!("starting ping task");
        let addr: SocketAddr = match self.endpoint {
            SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };

        let socket = tokio::net::UdpSocket::bind(addr).await?;
        let mut results = Vec::new();
        let mut buf = [0; u16::MAX as usize];

        for _ in 0..self.amount {
            let ping = Protocol::ping();
            socket
                .send_to(&ping.encode(), &self.endpoint)
                .await
                .unwrap();

            let Ok(socket_result) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                socket.recv_from(&mut buf),
            )
            .await
            else {
                tracing::error!(endpoint=%self.endpoint, "exceeded timeout duration");
                continue;
            };

            let size = match socket_result {
                Ok((size, _)) => size,
                Err(error) => {
                    tracing::error!(%error, "unable to receive data from socket");
                    continue;
                }
            };

            let recv_time = chrono::Utc::now().timestamp_nanos();
            let reply = Protocol::parse(&buf[..size]).unwrap().unwrap();

            if ping.nonce() != reply.nonce() {
                tracing::error!(sent_nonce=%ping.nonce(), recv_nonce=%reply.nonce(), "mismatched nonces");
                continue;
            }

            let delay = reply.round_trip_delay(recv_time).unwrap();
            let duration = std::time::Duration::from_nanos(delay as u64);
            tracing::info!(delay_millis=%format!("{:.2}", duration.as_secs_f64() * 1000.0), "successful ping");
            results.push(delay);
        }

        match median(&mut results) {
            Some(median) => {
                let median = std::time::Duration::from_nanos(median as u64);
                let average = std::time::Duration::from_nanos(
                    (results.iter().sum::<i64>() / results.len() as i64) as u64,
                );
                tracing::info!(
                    median_millis=%format!("{:.2}", median.as_secs_f64() * 1000.0),
                    average_millis=%format!("{:.2}", average.as_secs_f64() * 1000.0),
                    attempts=%self.amount,
                    successful_attempts=%results.len(),
                    "final results"
                );
            }
            None => tracing::error!("no successful results"),
        }

        Ok(())
    }
}

fn median(numbers: &mut [i64]) -> Option<i64> {
    let len = numbers.len();
    if len == 0 {
        return None;
    }

    // Sort the slice
    numbers.sort();

    if len % 2 == 1 {
        // Odd number of elements: Return the middle one.
        Some(numbers[len / 2])
    } else {
        // Even number of elements: Return the average of the two middle ones.
        let mid1 = numbers[(len - 1) / 2];
        let mid2 = numbers[len / 2];
        Some((mid1 + mid2) / 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        assert_eq!(median(&mut []), None);
    }

    #[test]
    fn single() {
        assert_eq!(median(&mut [42]), Some(42));
    }

    #[test]
    fn odd() {
        assert_eq!(median(&mut [3, 1, 2]), Some(2));
    }

    #[test]
    fn even() {
        assert_eq!(median(&mut [4, 3, 1, 2]), Some(2));
    }
}
