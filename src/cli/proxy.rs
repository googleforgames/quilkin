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

use std::{net::SocketAddr, sync::Arc, time::Duration};

use tonic::transport::Endpoint;

use crate::{proxy::SessionMap, utils::net, xds::ResourceType, Config, Result};

#[cfg(doc)]
use crate::filters::FilterFactory;

define_port!(7777);

/// Run Quilkin as a UDP reverse proxy.
#[derive(clap::Args, Clone, Debug)]
pub struct Proxy {
    /// One or more `quilkin manage` endpoints to listen to for config changes
    #[clap(short, long, env = "QUILKIN_MANAGEMENT_SERVER", conflicts_with("to"))]
    pub management_server: Vec<Endpoint>,
    /// The remote URL or local file path to retrieve the Maxmind database.
    #[clap(long, env)]
    pub mmdb: Option<crate::maxmind_db::Source>,
    /// The port to listen on.
    #[clap(short, long, env = super::PORT_ENV_VAR, default_value_t = PORT)]
    pub port: u16,
    /// One or more socket addresses to forward packets to.
    #[clap(short, long, env = "QUILKIN_DEST")]
    pub to: Vec<SocketAddr>,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            management_server: <_>::default(),
            mmdb: <_>::default(),
            port: PORT,
            to: <_>::default(),
        }
    }
}

impl Proxy {
    /// Start and run a proxy.
    pub async fn run(
        &self,
        config: std::sync::Arc<crate::Config>,
        mut shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> crate::Result<()> {
        const SESSION_TIMEOUT_SECONDS: Duration = Duration::from_secs(60);
        const SESSION_EXPIRY_POLL_INTERVAL: Duration = Duration::from_secs(60);

        let _mmdb_task = self.mmdb.clone().map(|source| {
            tokio::spawn(async move {
                use crate::config::BACKOFF_INITIAL_DELAY_MILLISECONDS;
                while let Err(error) =
                    tryhard::retry_fn(|| crate::MaxmindDb::update(source.clone()))
                        .retries(10)
                        .exponential_backoff(std::time::Duration::from_millis(
                            BACKOFF_INITIAL_DELAY_MILLISECONDS,
                        ))
                        .await
                {
                    tracing::warn!(%error, "error updating maxmind database");
                }
            })
        });

        if !self.to.is_empty() {
            config.clusters.value().default_cluster_mut().localities =
                vec![self.to.clone().into()].into();
        }

        if config.clusters.value().endpoints().count() == 0 && self.management_server.is_empty() {
            return Err(eyre::eyre!(
                "`quilkin proxy` requires at least one `to` address or `management_server` endpoint."
            ));
        }

        let id = config.id.load();
        tracing::info!(port = self.port, proxy_id = &*id, "Starting");

        let sessions = SessionMap::new(SESSION_TIMEOUT_SECONDS, SESSION_EXPIRY_POLL_INTERVAL);

        let _xds_stream = if !self.management_server.is_empty() {
            let client =
                crate::xds::AdsClient::connect(String::clone(&id), self.management_server.clone())
                    .await?;
            let mut stream = client.xds_client_stream(config.clone());

            tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
            stream
                .discovery_request(ResourceType::Endpoint, &[])
                .await?;
            tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
            stream
                .discovery_request(ResourceType::Listener, &[])
                .await?;
            Some((client, stream))
        } else {
            None
        };

        self.run_recv_from(&config, sessions.clone())?;
        tracing::info!("Quilkin is ready");

        shutdown_rx
            .changed()
            .await
            .map_err(|error| eyre::eyre!(error))?;

        tracing::info!(sessions=%sessions.len(), "waiting for active sessions to expire");
        while sessions.is_not_empty() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tracing::debug!(sessions=%sessions.len(), "sessions still active");
        }
        tracing::info!("all sessions expired");

        Ok(())
    }

    /// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
    /// Each received packet is placed on a queue to be processed by a worker task.
    /// This function also spawns the set of worker tasks responsible for consuming packets
    /// off the aforementioned queue and processing them through the filter chain and session
    /// pipeline.
    fn run_recv_from(&self, config: &Arc<Config>, sessions: SessionMap) -> Result<()> {
        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = num_cpus::get();

        // Contains config for each worker task.
        let mut workers = Vec::with_capacity(num_workers);
        for worker_id in 0..num_workers {
            let socket = Arc::new(net::socket_with_reuse(self.port)?);
            workers.push(crate::proxy::DownstreamReceiveWorkerConfig {
                worker_id,
                socket: socket.clone(),
                config: config.clone(),
                sessions: sessions.clone(),
            })
        }

        // Start the worker tasks that pick up received packets from their queue
        // and processes them.
        for worker in workers {
            worker.spawn();
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::time::{timeout, Duration};

    use crate::{
        config,
        endpoint::Endpoint,
        test_utils::{available_addr, create_socket, load_test_filters, TestHelper},
    };

    #[tokio::test]
    async fn run_server() {
        let mut t = TestHelper::default();

        let endpoint1 = t.open_socket_and_recv_single_packet().await;
        let endpoint2 = t.open_socket_and_recv_single_packet().await;

        let local_addr = available_addr().await;
        let proxy = crate::cli::Proxy {
            port: local_addr.port(),
            ..<_>::default()
        };

        let config = Arc::new(crate::Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default(vec![
                Endpoint::new(endpoint1.socket.local_addr().unwrap().into()),
                Endpoint::new(endpoint2.socket.local_addr().unwrap().into()),
            ])
        });

        t.run_server(config, proxy, None);

        let msg = "hello";
        endpoint1
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(1), endpoint1.packet_rx)
                .await
                .expect("should get a packet")
                .unwrap()
        );
        assert_eq!(
            msg,
            timeout(Duration::from_secs(1), endpoint2.packet_rx)
                .await
                .expect("should get a packet")
                .unwrap()
        );
    }

    #[tokio::test]
    async fn run_client() {
        let mut t = TestHelper::default();

        let endpoint = t.open_socket_and_recv_single_packet().await;

        let local_addr = available_addr().await;
        let proxy = crate::cli::Proxy {
            port: local_addr.port(),
            ..<_>::default()
        };
        let config = Arc::new(Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default(vec![Endpoint::new(
                endpoint.socket.local_addr().unwrap().into(),
            )])
        });
        t.run_server(config, proxy, None);

        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_millis(100), endpoint.packet_rx)
                .await
                .unwrap()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn run_with_filter() {
        let mut t = TestHelper::default();

        load_test_filters();
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = available_addr().await;
        let config = Arc::new(Config::default());
        config.filters.store(
            crate::filters::FilterChain::try_from(vec![config::Filter {
                name: "TestFilter".to_string(),
                label: None,
                config: None,
            }])
            .map(Arc::new)
            .unwrap(),
        );
        config.clusters.modify(|clusters| {
            clusters.insert_default(vec![Endpoint::new(
                endpoint.socket.local_addr().unwrap().into(),
            )])
        });
        t.run_server(
            config,
            crate::cli::Proxy {
                port: local_addr.port(),
                ..<_>::default()
            },
            None,
        );

        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &local_addr)
            .await
            .unwrap();

        // search for the filter strings.
        let result = timeout(Duration::from_millis(100), endpoint.packet_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(result.contains(msg), "'{}' not found in '{}'", msg, result);
        assert!(result.contains(":odr:"), ":odr: not found in '{}'", result);
    }

    #[tokio::test]
    async fn spawn_downstream_receive_workers() {
        let t = TestHelper::default();

        let socket = Arc::new(create_socket().await);
        let addr = socket.local_addr().unwrap();
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let msg = "hello";
        let config = Arc::new(Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default(vec![endpoint.socket.local_addr().unwrap()])
        });

        // we'll test a single DownstreamReceiveWorkerConfig
        crate::proxy::DownstreamReceiveWorkerConfig {
            worker_id: 1,
            socket: socket.clone(),
            config,
            sessions: <_>::default(),
        }
        .spawn();

        let socket = create_socket().await;
        socket.send_to(msg.as_bytes(), &addr).await.unwrap();

        assert_eq!(
            msg,
            timeout(Duration::from_secs(1), endpoint.packet_rx)
                .await
                .expect("should receive a packet")
                .unwrap()
        );
    }

    #[tokio::test]
    async fn run_recv_from() {
        let t = TestHelper::default();

        let msg = "hello";
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = available_addr().await;
        let proxy = crate::cli::Proxy {
            port: local_addr.port(),
            ..<_>::default()
        };

        let config = Arc::new(crate::Config::default());
        config.clusters.modify(|clusters| {
            clusters.insert_default(vec![endpoint.socket.local_addr().unwrap()])
        });

        proxy.run_recv_from(&config, <_>::default()).unwrap();

        let socket = create_socket().await;
        socket.send_to(msg.as_bytes(), &local_addr).await.unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(1), endpoint.packet_rx)
                .await
                .expect("should receive a packet")
                .unwrap()
        );
    }
}
