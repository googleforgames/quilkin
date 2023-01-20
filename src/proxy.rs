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

pub use sessions::{Session, SessionArgs, SessionKey};

use std::{
    net::{Ipv6Addr, SocketAddrV6},
    sync::Arc,
};

use prometheus::HistogramTimer;
use tokio::{net::UdpSocket, sync::watch, time::Duration};

use crate::{
    endpoint::{Endpoint, EndpointAddress},
    filters::{Filter, ReadContext},
    proxy::sessions::SessionMap,
    ttl_map::TryResult,
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
    sessions: SessionMap,
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
    config: Arc<Config>,
    sessions: SessionMap,
    /// The worker task exits when a value is received from this shutdown channel.
    shutdown_rx: watch::Receiver<()>,
}

impl DownstreamReceiveWorkerConfig {
    fn spawn(self) {
        let Self {
            worker_id,
            socket,
            config,
            sessions,
            mut shutdown_rx,
        } = self;

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
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((size, source)) => Self::spawn_process_task(&buf, size, source, worker_id, &socket, &config, &sessions),
                            Err(error) => {
                                tracing::error!(%error, "error receiving packet");
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

    #[inline]
    fn spawn_process_task(
        buf: &[u8],
        size: usize,
        source: std::net::SocketAddr,
        worker_id: usize,
        socket: &Arc<UdpSocket>,
        config: &Arc<Config>,
        sessions: &SessionMap,
    ) {
        let timer = crate::metrics::processing_time(crate::metrics::READ).start_timer();
        let contents = buf[..size].to_vec();

        tracing::trace!(
            id = worker_id,
            size = size,
            source = %source,
            contents=&*debug::bytes_to_string(&contents),
            "received packet from downstream"
        );

        let packet = DownstreamPacket {
            source: source.into(),
            contents,
            timer,
        };
        let config = config.clone();
        let sessions = sessions.clone();
        let socket = socket.clone();

        tokio::spawn(async move {
            match Self::process_downstream_received_packet(packet, config, socket, sessions).await {
                Ok(size) => {
                    crate::metrics::packets_total(crate::metrics::READ).inc();
                    crate::metrics::bytes_total(crate::metrics::READ).inc_by(size as u64);
                }
                Err(error) => {
                    crate::metrics::packets_dropped_total(
                        crate::metrics::READ,
                        "proxy::Session::send",
                    )
                    .inc();
                    crate::metrics::errors_total(crate::metrics::READ).inc();
                    tracing::error!(kind=%error.kind(), "{}", error);
                }
            }
        });
    }

    /// Processes a packet by running it through the filter chain.
    async fn process_downstream_received_packet(
        packet: DownstreamPacket,
        config: Arc<Config>,
        downstream_socket: Arc<UdpSocket>,
        sessions: SessionMap,
    ) -> std::io::Result<usize> {
        let clusters = config.clusters.load();
        let endpoints: Vec<_> = clusters.endpoints().collect();
        if endpoints.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "dropping packet, no upstream endpoints available",
            ));
        }

        let filters = config.filters.load();
        let mut context = ReadContext::new(endpoints, packet.source, packet.contents);
        let result = filters.read(&mut context);

        let mut bytes_written = 0;
        if let Some(()) = result {
            for endpoint in context.endpoints.iter() {
                bytes_written += Self::session_send_packet(
                    &context.contents,
                    &context.source,
                    endpoint,
                    &downstream_socket,
                    &config,
                    &sessions,
                )
                .await?;
            }
        }

        packet.timer.stop_and_record();
        Ok(bytes_written)
    }

    /// Send a packet received from `recv_addr` to an endpoint.
    #[tracing::instrument(level="trace", skip_all, fields(source = %recv_addr, dest = %endpoint.address))]
    async fn session_send_packet(
        packet: &[u8],
        recv_addr: &EndpointAddress,
        endpoint: &Endpoint,
        downstream_socket: &Arc<UdpSocket>,
        config: &Arc<Config>,
        sessions: &SessionMap,
    ) -> std::io::Result<usize> {
        let session_key = SessionKey {
            source: recv_addr.clone(),
            dest: endpoint.address.clone(),
        };

        let send_future = match sessions.try_get(&session_key) {
            TryResult::Present(entry) => entry.send(packet),
            TryResult::Absent => {
                let session_args = SessionArgs {
                    config: config.clone(),
                    source: session_key.source.clone(),
                    downstream_socket: downstream_socket.clone(),
                    dest: endpoint.clone(),
                };

                let session = session_args.into_session().await?;
                let future = session.send(packet);
                sessions.insert(session_key, session);
                future
            }
            TryResult::Locked => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    eyre::eyre!("dropping packet as the session shard is currently locked"),
                ));
            }
        };

        send_future.await
    }
}

impl Proxy {
    /// Returns a builder for configuring a Quilkin proxy.
    pub fn builder() -> crate::config::Builder {
        <_>::default()
    }

    /// start the async processing of incoming UDP packets. Will block until an
    /// event is sent through the stop Receiver.
    pub async fn run(self, mut shutdown_rx: watch::Receiver<()>) -> Result<()> {
        const SESSION_TIMEOUT_SECONDS: Duration = Duration::from_secs(60);
        const SESSION_EXPIRY_POLL_INTERVAL: Duration = Duration::from_secs(60);
        tracing::info!(
            port = *self.config.port.load(),
            proxy_id = &*self.config.id.load(),
            "Starting"
        );

        let sessions = SessionMap::new(SESSION_TIMEOUT_SECONDS, SESSION_EXPIRY_POLL_INTERVAL);

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
            sessions,
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
    async fn run_recv_from(
        &self,
        RunRecvFromArgs {
            sessions,
            shutdown_rx,
        }: RunRecvFromArgs,
    ) -> Result<()> {
        // The number of worker tasks to spawn. Each task gets a dedicated queue to
        // consume packets off.
        let num_workers = num_cpus::get();

        // Contains config for each worker task.
        let mut workers = Vec::with_capacity(num_workers);
        for worker_id in 0..num_workers {
            let socket = Arc::new(self.bind(*self.config.port.load())?);
            workers.push(DownstreamReceiveWorkerConfig {
                worker_id,
                socket: socket.clone(),
                shutdown_rx: shutdown_rx.clone(),
                config: self.config.clone(),
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

    /// binds the local configured port with port and address reuse applied.
    fn bind(&self, port: u16) -> Result<UdpSocket> {
        let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
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
        DownstreamReceiveWorkerConfig {
            worker_id: 1,
            socket: socket.clone(),
            config: Arc::new(
                Config::builder()
                    .endpoints(&[endpoint.socket.local_addr().unwrap().into()][..])
                    .build()
                    .unwrap(),
            ),
            sessions: <_>::default(),
            shutdown_rx,
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
        let (_shutdown_tx, shutdown_rx) = watch::channel(());

        let msg = "hello";
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let local_addr = available_addr().await;
        let config = Config::builder()
            .port(local_addr.port())
            .endpoints(&[Endpoint::from(endpoint.socket.local_addr().unwrap())][..])
            .build()
            .unwrap();
        let server = Proxy::try_from(config).unwrap();

        server
            .run_recv_from(RunRecvFromArgs {
                sessions: <_>::default(),
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
