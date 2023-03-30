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

/// Common utilities for testing
use std::{net::SocketAddr, str::from_utf8, sync::Arc};

use once_cell::sync::Lazy;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, watch},
};

use crate::{
    cluster::Cluster,
    config::Config,
    endpoint::{Endpoint, EndpointAddress, LocalityEndpoints},
    filters::{prelude::*, FilterRegistry},
    metadata::Value,
};

static ENABLE_LOG: Lazy<()> = Lazy::new(|| {
    tracing_subscriber::fmt()
        .pretty()
        .with_max_level(tracing::Level::TRACE)
        .init()
});

/// Call to safely enable `tracing` logging calls, at the TRACE level.
/// This can be very useful when attempting to debug unit and integration tests.
pub fn enable_tracing_log() {
    Lazy::force(&ENABLE_LOG);
}

/// Returns a local address on a port that is not assigned to another test.
pub async fn available_addr() -> SocketAddr {
    let socket = create_socket().await;
    let addr = socket.local_addr().unwrap();
    tracing::debug!(addr = ?addr, "test_util::available_addr");
    addr
}

// TestFilter is useful for testing that commands are executing filters appropriately.
pub struct TestFilter;

#[async_trait::async_trait]
impl Filter for TestFilter {
    async fn read(&self, ctx: &mut ReadContext) -> Result<(), FilterError> {
        // append values on each run
        ctx.metadata
            .entry("downstream".into())
            .and_modify(|e| e.as_mut_string().unwrap().push_str(":receive"))
            .or_insert_with(|| Value::String("receive".into()));

        ctx.contents
            .append(&mut format!(":odr:{}", ctx.source).into_bytes());
        Ok(())
    }

    async fn write(&self, ctx: &mut WriteContext) -> Result<(), FilterError> {
        // append values on each run
        ctx.metadata
            .entry("upstream".into())
            .and_modify(|e| e.as_mut_string().unwrap().push_str(":receive"))
            .or_insert_with(|| Value::String("receive".to_string()));

        ctx.contents
            .append(&mut format!(":our:{}:{}", ctx.source, ctx.dest).into_bytes());
        Ok(())
    }
}

impl StaticFilter for TestFilter {
    const NAME: &'static str = "TestFilter";
    type Configuration = ();
    type BinaryConfiguration = ();

    fn try_from_config(_: Option<Self::Configuration>) -> Result<Self, CreationError> {
        Ok(Self)
    }
}

#[derive(Default)]
pub struct TestHelper {
    /// Channel to subscribe to, and trigger the shutdown of created resources.
    shutdown_ch: Option<(watch::Sender<()>, watch::Receiver<()>)>,
    server_shutdown_tx: Vec<Option<watch::Sender<()>>>,
}

/// Returned from [creating a socket](TestHelper::open_socket_and_recv_single_packet)
pub struct OpenSocketRecvPacket {
    /// The opened socket
    pub socket: Arc<UdpSocket>,
    /// A channel on which the received packet will be forwarded.
    pub packet_rx: oneshot::Receiver<String>,
}

impl Drop for TestHelper {
    fn drop(&mut self) {
        for shutdown_tx in self.server_shutdown_tx.iter_mut().flat_map(|tx| tx.take()) {
            shutdown_tx
                .send(())
                .map_err(|error| {
                    tracing::warn!(
                        %error,
                        "Failed to send server shutdown over channel"
                    )
                })
                .ok();
        }

        if let Some((shutdown_tx, _)) = self.shutdown_ch.take() {
            shutdown_tx.send(()).unwrap();
        }
    }
}

impl TestHelper {
    /// Opens a socket, listening for a packet. Once a packet is received, it
    /// is forwarded over the returned channel.
    pub async fn open_socket_and_recv_single_packet(&self) -> OpenSocketRecvPacket {
        let socket = Arc::new(create_socket().await);
        let (packet_tx, packet_rx) = oneshot::channel::<String>();
        let socket_recv = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let size = socket_recv.recv(&mut buf).await.unwrap();
            packet_tx
                .send(from_utf8(&buf[..size]).unwrap().to_string())
                .unwrap();
        });
        OpenSocketRecvPacket { socket, packet_rx }
    }

    /// Opens a socket, listening for packets. Received packets are forwarded over the
    /// returned channel.
    pub async fn open_socket_and_recv_multiple_packets(
        &mut self,
    ) -> (mpsc::Receiver<String>, Arc<UdpSocket>) {
        let (packet_tx, packet_rx) = mpsc::channel::<String>(10);
        let socket = Arc::new(create_socket().await);
        let mut shutdown_rx = self.get_shutdown_subscriber().await;
        let socket_recv = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            loop {
                tokio::select! {
                    received = socket_recv.recv_from(&mut buf) => {
                        let (size, _) = received.unwrap();
                        let str = from_utf8(&buf[..size]).unwrap().to_string();
                        match packet_tx.send(str).await {
                            Ok(_) => {}
                            Err(error) => {
                                tracing::warn!(target: "recv_multiple_packets", %error, "recv_chan dropped");
                                return;
                            }
                        };
                    },
                    _ = shutdown_rx.changed() => {
                        return;
                    }
                }
            }
        });
        (packet_rx, socket)
    }

    /// Runs a simple UDP server that echos back payloads.
    /// Returns the server's address.
    pub async fn run_echo_server(&mut self) -> EndpointAddress {
        self.run_echo_server_with_tap(|_, _, _| {}).await
    }

    /// Runs a simple UDP server that echos back payloads.
    /// The provided function is invoked for each received payload.
    /// Returns the server's address.
    pub async fn run_echo_server_with_tap<F>(&mut self, tap: F) -> EndpointAddress
    where
        F: Fn(SocketAddr, &[u8], SocketAddr) + Send + 'static,
    {
        let socket = create_socket().await;
        let addr = socket.local_addr().unwrap();
        let mut shutdown = self.get_shutdown_subscriber().await;
        let local_addr = addr;
        tokio::spawn(async move {
            loop {
                let mut buf = vec![0; 1024];
                tokio::select! {
                    recvd = socket.recv_from(&mut buf) => {
                        let (size, sender) = recvd.unwrap();
                        let packet = &buf[..size];
                        tap(sender, packet, local_addr);
                        socket.send_to(packet, sender).await.unwrap();
                    },
                    _ = shutdown.changed() => {
                        return;
                    }
                }
            }
        });
        addr.into()
    }

    pub fn run_server_with_config(&mut self, config: Arc<Config>) {
        self.run_server(config, crate::cli::Proxy::default(), None)
    }

    pub fn run_server(
        &mut self,
        config: Arc<Config>,
        server: crate::cli::Proxy,
        with_admin: Option<Option<SocketAddr>>,
    ) {
        let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());
        self.server_shutdown_tx.push(Some(shutdown_tx));

        if let Some(address) = with_admin {
            tokio::spawn(crate::admin::server(
                crate::admin::Mode::Proxy,
                config.clone(),
                address,
            ));
        }

        tokio::spawn(async move {
            server.run(config, shutdown_rx).await.unwrap();
        });
    }

    /// Returns a receiver subscribed to the helper's shutdown event.
    async fn get_shutdown_subscriber(&mut self) -> watch::Receiver<()> {
        // If this is the first call, then we set up the channel first.
        match self.shutdown_ch {
            Some((_, ref rx)) => rx.clone(),
            None => {
                let ch = watch::channel(());
                let recv = ch.1.clone();
                self.shutdown_ch = Some(ch);
                recv
            }
        }
    }
}

/// assert that read makes no changes
pub async fn assert_filter_read_no_change<F>(filter: &F)
where
    F: Filter,
{
    let endpoints = vec!["127.0.0.1:80".parse::<Endpoint>().unwrap()];
    let source = "127.0.0.1:90".parse().unwrap();
    let contents = "hello".to_string().into_bytes();
    let mut context = ReadContext::new(endpoints.clone(), source, contents.clone());

    filter.read(&mut context).await.unwrap();
    assert_eq!(endpoints, &*context.endpoints);
    assert_eq!(contents, &*context.contents);
}

/// assert that write makes no changes
pub async fn assert_write_no_change<F>(filter: &F)
where
    F: Filter,
{
    let endpoint = "127.0.0.1:90".parse::<Endpoint>().unwrap();
    let contents = "hello".to_string().into_bytes();
    let mut context = WriteContext::new(
        endpoint.clone(),
        endpoint.address,
        "127.0.0.1:70".parse().unwrap(),
        contents.clone(),
    );

    filter.write(&mut context).await.unwrap();
    assert_eq!(contents, &*context.contents);
}

/// Opens a new socket bound to an ephemeral port
pub async fn create_socket() -> UdpSocket {
    crate::utils::net::socket_with_reuse(0).unwrap()
}

pub fn config_with_dummy_endpoint() -> Config {
    let config = Config::default();

    config.clusters.value().insert(Cluster {
        name: "default".into(),
        localities: vec![LocalityEndpoints {
            locality: None,
            endpoints: [Endpoint {
                address: (std::net::Ipv4Addr::LOCALHOST, 8080).into(),
                ..<_>::default()
            }]
            .into(),
        }]
        .into_iter()
        .collect(),
    });

    config
}
/// Creates a dummy endpoint with `id` as a suffix.
pub fn ep(id: u8) -> Endpoint {
    Endpoint {
        address: ([127, 0, 0, id], 8080).into(),
        ..<_>::default()
    }
}

pub fn new_test_config() -> crate::Config {
    crate::Config {
        filters: crate::config::Slot::new(
            crate::filters::FilterChain::try_from(vec![crate::config::Filter {
                name: "TestFilter".into(),
                label: None,
                config: None,
            }])
            .unwrap(),
        ),
        ..<_>::default()
    }
}

pub fn load_test_filters() {
    FilterRegistry::register([TestFilter::factory()]);
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use crate::test_utils::TestHelper;

    #[tokio::test]
    async fn test_echo_server() {
        let mut t = TestHelper::default();
        let echo_addr = t.run_echo_server().await;
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &echo_addr.to_socket_addr().await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), endpoint.packet_rx)
                .await
                .expect("should not timeout")
                .unwrap()
        );
    }
}
