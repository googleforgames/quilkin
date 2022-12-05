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

mod sessions;

pub use sessions::SessionKey;

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use prometheus::HistogramTimer;
use tokio::{net::UdpSocket, sync::watch, time::Duration};

use crate::{
    endpoint::{Endpoint, EndpointAddress},
    filters::{Filter, ReadContext},
    proxy::sessions::{manager::SessionManager, SessionArgs, SESSION_TIMEOUT_SECONDS},
    utils::{debug, net},
    xds::ResourceType,
    Config, Result,
};

/// The UDP proxy service.
pub struct Proxy {
    pub config: Arc<Config>,
}

impl TryFrom<Config> for Proxy {
    type Error = eyre::Error;
    fn try_from(config: Config) -> Result<Self, Self::Error> {
        Ok(Self {
            config: Arc::from(config),
        })
    }
}

impl TryFrom<Arc<Config>> for Proxy {
    type Error = eyre::Error;
    fn try_from(config: Arc<Config>) -> Result<Self, Self::Error> {
        Ok(Self { config })
    }
}

/// Represents arguments to the `Proxy::run_recv_from` method.
struct RunRecvFromArgs {
    session_manager: SessionManager,
    session_ttl: Duration,
    shutdown_rx: watch::Receiver<()>,
}

/// Packet received from local port
#[derive(Debug)]
struct DownstreamPacket {
    source: EndpointAddress,
    contents: Vec<u8>,
    timer: HistogramTimer,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
struct DownstreamReceiveWorkerConfig {
    /// ID of the worker.
    worker_id: usize,
    /// Socket with reused port from which the worker receives packets.
    socket: Arc<UdpSocket>,
    /// Configuration required to process a received downstream packet.
    receive_config: ProcessDownstreamReceiveConfig,
    /// The worker task exits when a value is received from this shutdown channel.
    shutdown_rx: watch::Receiver<()>,
}

/// Contains arguments to process a received downstream packet, through the
/// filter chain and session pipeline.
struct ProcessDownstreamReceiveConfig {
    config: Arc<Config>,
    session_manager: SessionManager,
    session_ttl: Duration,
    socket: Arc<UdpSocket>,
}

impl Proxy {
    /// Returns a builder for configuring a Quilkin proxy.
    pub fn builder() -> crate::config::Builder {
        <_>::default()
    }

    /// start the async processing of incoming UDP packets. Will block until an
    /// event is sent through the stop Receiver.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
        tracing::info!(
            port = *self.config.port.load(),
            proxy_id = &*self.config.id.load(),
            "Starting"
        );

        let session_manager = SessionManager::new(shutdown_rx.clone());
        let session_ttl = Duration::from_secs(SESSION_TIMEOUT_SECONDS);

        let management_servers = self.config.management_servers.load();
        let _xds_stream = if !management_servers.is_empty() {
            let client = crate::xds::Client::connect(self.config.clone()).await?;
            let mut stream = client.stream().await?;

            tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
            stream.send(ResourceType::Endpoint, &[]).await?;
            tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
            stream.send(ResourceType::Listener, &[]).await?;
            Some(stream)
        } else {
            None
        };

        self.run_recv_from(RunRecvFromArgs {
            session_manager,
            session_ttl,
            shutdown_rx: shutdown_rx.clone(),
        })
        .await?;
        tracing::info!("Quilkin is ready");

        shutdown_rx
            .changed()
            .await
            .map_err(|error| eyre::eyre!(error))
    }

    /// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
    /// Each received packet is placed on a queue to be processed by a worker task.
    /// This function also spawns the set of worker tasks responsible for consuming packets
    /// off the aforementioned queue and processing them through the filter chain and session
    /// pipeline.
    async fn run_recv_from(&self, args: RunRecvFromArgs) -> Result<()> {
        let session_manager = args.session_manager;

        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = num_cpus::get();

        // Contains config for each worker task.
        let mut worker_configs = vec![];
        for worker_id in 0..num_workers {
            let socket = Arc::new(self.bind(*self.config.port.load())?);
            worker_configs.push(DownstreamReceiveWorkerConfig {
                worker_id,
                socket: socket.clone(),
                shutdown_rx: args.shutdown_rx.clone(),
                receive_config: ProcessDownstreamReceiveConfig {
                    config: self.config.clone(),
                    session_manager: session_manager.clone(),
                    session_ttl: args.session_ttl,
                    socket,
                },
            })
        }

        // Start the worker tasks that pick up received packets from their queue
        // and processes them.
        Self::spawn_downstream_receive_workers(worker_configs);
        Ok(())
    }

    /// For each worker config provided, spawn a background task that sits in a
    /// loop, receiving packets from a socket and processing them through
    /// the filter chain.
    fn spawn_downstream_receive_workers(worker_configs: Vec<DownstreamReceiveWorkerConfig>) {
        for DownstreamReceiveWorkerConfig {
            worker_id,
            socket,
            mut shutdown_rx,
            receive_config,
        } in worker_configs
        {
            tokio::spawn(async move {
                // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
                // packet, which is the maximum value of 16 a bit integer.
                let mut buf = vec![0; 1 << 16];
                loop {
                    tracing::debug!(
                        id = worker_id,
                        addr = ?socket.local_addr(),
                        "Awaiting packet"
                    );
                    tokio::select! {
                        recv = socket.recv_from(&mut buf) => {
                            let timer = crate::metrics::processing_time(crate::metrics::READ).start_timer();
                            match recv {
                                Ok((size, source)) => {
                                    let contents = buf[..size].to_vec();
                                    tracing::trace!(id = worker_id, size = size, source = %source, contents=&*debug::bytes_to_string(&contents), "received packet from downstream");
                                    let packet = DownstreamPacket {
                                        source: source.into(),
                                        contents,
                                        timer,
                                    };
                                    Self::process_downstream_received_packet(packet, &receive_config).await
                                },
                                Err(error) => {
                                    tracing::error!(%error);
                                    return;
                                }
                            }
                        }
                        _ = shutdown_rx.changed() => {
                            tracing::debug!(id = worker_id, "Received shutdown signal");
                            return;
                        }
                    }
                }
            });
        }
    }

    /// Processes a packet by running it through the filter chain.
    async fn process_downstream_received_packet(
        packet: DownstreamPacket,
        args: &ProcessDownstreamReceiveConfig,
    ) {
        let clusters = args.config.clusters.load();
        let endpoints: Vec<_> = clusters.endpoints().collect();
        if endpoints.is_empty() {
            tracing::trace!("dropping packet, no upstream endpoints available");
            crate::metrics::packets_dropped_total(crate::metrics::READ, "NoEndpointsAvailable")
                .inc();
            return;
        }

        let filters = args.config.filters.load();
        let mut context = ReadContext::new(endpoints, packet.source, packet.contents);
        let result = filters.read(&mut context);

        if let Some(()) = result {
            for endpoint in context.endpoints.iter() {
                Self::session_send_packet(
                    &context.contents,
                    context.source.clone(),
                    endpoint,
                    args,
                )
                .await;
            }
        }

        packet.timer.stop_and_record();
    }

    /// Send a packet received from `recv_addr` to an endpoint.
    #[tracing::instrument(level="trace", skip_all, fields(source = %recv_addr, dest = %endpoint.address))]
    async fn session_send_packet(
        packet: &[u8],
        recv_addr: EndpointAddress,
        endpoint: &Endpoint,
        args: &ProcessDownstreamReceiveConfig,
    ) {
        let session_key = SessionKey {
            source: recv_addr,
            dest: endpoint.address.clone(),
        };

        // Grab a read lock and find the session.
        let guard = args.session_manager.get_sessions().await;
        if let Some(session) = guard.get(&session_key) {
            // If it exists then send the packet, we're done.
            session.send(packet, args.session_ttl).await
        } else {
            // If it does not exist, grab a write lock so that we can create it.
            //
            // NOTE: We must drop the lock guard to release the lock before
            // trying to acquire a write lock since these lock aren't reentrant,
            // otherwise we will deadlock with our self.
            drop(guard);

            // Grab a write lock.
            let mut guard = args.session_manager.get_sessions_mut().await;

            // Although we have the write lock now, check whether some other thread
            // managed to create the session in-between our dropping the read
            // lock and grabbing the write lock.
            if let Some(session) = guard.get(&session_key) {
                tracing::trace!("Reusing previous session");
                // If the session now exists then we have less work to do,
                // simply send the packet.
                session.send(packet, args.session_ttl).await;
            } else {
                tracing::trace!("Creating new session");
                // Otherwise, create the session and insert into the map.
                let session_args = SessionArgs {
                    config: args.config.clone(),
                    source: session_key.source.clone(),
                    downstream_socket: args.socket.clone(),
                    dest: endpoint.clone(),
                    ttl: args.session_ttl,
                };
                match session_args.into_session().await {
                    Ok(session) => {
                        // Insert the session into the map and release the write lock
                        // immediately since we don't want to block other threads while we send
                        // the packet. Instead, re-acquire a read lock and send the packet.
                        guard.insert(session.key(), session);

                        // Release the write lock.
                        drop(guard);

                        // Grab a read lock to send the packet.
                        let guard = args.session_manager.get_sessions().await;
                        if let Some(session) = guard.get(&session_key) {
                            session.send(packet, args.session_ttl).await;
                        } else {
                            tracing::warn!(
                                key = %format!("({}:{})", session_key.source, session_key.dest),
                                "Could not find session"
                            )
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "Failed to ensure session exists");
                    }
                }
            }
        }
    }

    /// binds the local configured port with port and address reuse applied.
    fn bind(&self, port: u16) -> Result<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        net::socket_with_reuse(addr.into())
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
        let config = Config::builder()
            .port(local_addr.port())
            .endpoints(vec![
                Endpoint::new(endpoint1.socket.local_addr().unwrap().into()),
                Endpoint::new(endpoint2.socket.local_addr().unwrap().into()),
            ])
            .build()
            .unwrap();
        t.run_server_with_config(config);

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
        let config = Config::builder()
            .port(local_addr.port())
            .endpoints(vec![Endpoint::new(
                endpoint.socket.local_addr().unwrap().into(),
            )])
            .build()
            .unwrap();
        t.run_server_with_config(config);

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
        let config = Config::builder()
            .port(local_addr.port())
            .filters(vec![config::Filter {
                name: "TestFilter".to_string(),
                config: None,
            }])
            .endpoints(vec![Endpoint::new(
                endpoint.socket.local_addr().unwrap().into(),
            )])
            .build()
            .unwrap();
        t.run_server_with_config(config);

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
        let (_shutdown_tx, shutdown_rx) = watch::channel(());
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let msg = "hello";

        // we'll test a single DownstreamReceiveWorkerConfig
        let config = DownstreamReceiveWorkerConfig {
            worker_id: 1,
            socket: socket.clone(),
            receive_config: ProcessDownstreamReceiveConfig {
                config: Arc::new(
                    Config::builder()
                        .endpoints(&[endpoint.socket.local_addr().unwrap().into()][..])
                        .build()
                        .unwrap(),
                ),
                session_manager: SessionManager::new(shutdown_rx.clone()),
                session_ttl: Duration::from_secs(10),
                socket,
            },
            shutdown_rx,
        };

        Proxy::spawn_downstream_receive_workers(vec![config]);

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
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        let msg = "hello";
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let session_manager = SessionManager::new(shutdown_rx.clone());
        let local_addr = available_addr().await;
        let config = Config::builder()
            .port(local_addr.port())
            .endpoints(&[Endpoint::from(endpoint.socket.local_addr().unwrap())][..])
            .build()
            .unwrap();
        let server = Proxy::try_from(config).unwrap();

        server
            .run_recv_from(RunRecvFromArgs {
                session_manager: session_manager.clone(),
                session_ttl: Duration::from_secs(10),
                shutdown_rx,
            })
            .await
            .unwrap();

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
