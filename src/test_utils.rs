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
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::from_utf8;
use std::sync::Arc;

use slog::{o, warn, Drain, Logger};
use slog_term::{FullFormat, PlainSyncDecorator};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};

use crate::config::{Builder as ConfigBuilder, Config};
use crate::endpoint::{Endpoint, Endpoints};
use crate::filters::{prelude::*, FilterChain, FilterRegistry, FilterSet};
use crate::proxy::{Builder, PendingValidation};

pub struct TestFilterFactory {}
impl FilterFactory for TestFilterFactory {
    fn name(&self) -> &'static str {
        "TestFilter"
    }

    fn create_filter(&self, _: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(TestFilter {}))
    }
}

// TestFilter is useful for testing that commands are executing filters appropriately.
pub struct TestFilter {}

impl Filter for TestFilter {
    fn read(&self, mut ctx: ReadContext) -> Option<ReadResponse> {
        // append values on each run
        ctx.metadata
            .entry(Arc::new("downstream".into()))
            .and_modify(|e| e.downcast_mut::<String>().unwrap().push_str(":receive"))
            .or_insert_with(|| Box::new("receive".to_string()));

        ctx.contents
            .append(&mut format!(":odr:{}", ctx.from).into_bytes());
        Some(ctx.into())
    }

    fn write(&self, mut ctx: WriteContext) -> Option<WriteResponse> {
        // append values on each run
        ctx.metadata
            .entry("upstream".into())
            .and_modify(|e| e.downcast_mut::<String>().unwrap().push_str(":receive"))
            .or_insert_with(|| Box::new("receive".to_string()));

        ctx.contents
            .append(&mut format!(":our:{}:{}", ctx.from, ctx.to).into_bytes());
        Some(ctx.into())
    }
}

// logger returns a standard out, non structured terminal logger, suitable for using in tests,
// since it's more human readable.
pub fn logger() -> Logger {
    let plain = PlainSyncDecorator::new(std::io::stdout());
    let drain = FullFormat::new(plain).build().fuse();
    Logger::root(drain, o!())
}

pub struct TestHelper {
    pub log: Logger,
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
        let log = self.log.clone();
        for shutdown_tx in self
            .server_shutdown_tx
            .iter_mut()
            .map(|tx| tx.take())
            .flatten()
        {
            shutdown_tx
                .send(())
                .map_err(|err| {
                    warn!(
                        log,
                        "Failed to send server shutdown over channel"; "error" => %err
                    )
                })
                .ok();
        }

        if let Some((shutdown_tx, _)) = self.shutdown_ch.take() {
            shutdown_tx.send(()).unwrap();
        }
    }
}

impl Default for TestHelper {
    fn default() -> Self {
        TestHelper {
            log: logger(),
            shutdown_ch: None,
            server_shutdown_tx: vec![],
        }
    }
}

impl TestHelper {
    /// Opens a new socket bound to an ephemeral port
    pub async fn create_socket(&self) -> Arc<UdpSocket> {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        Arc::new(UdpSocket::bind(addr).await.unwrap())
    }

    /// Opens a socket, listening for a packet. Once a packet is received, it
    /// is forwarded over the returned channel.
    pub async fn open_socket_and_recv_single_packet(&self) -> OpenSocketRecvPacket {
        let socket = self.create_socket().await;
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
        let socket = self.create_socket().await;
        let log = self.log.clone();
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
                            Err(err) => {
                                warn!(log, "recv_multiple_packets: recv_chan dropped"; "error" => %err);
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
    pub async fn run_echo_server(&mut self) -> SocketAddr {
        self.run_echo_server_with_tap(|_, _, _| {}).await
    }

    /// Runs a simple UDP server that echos back payloads.
    /// The provided function is invoked for each received payload.
    /// Returns the server's address.
    pub async fn run_echo_server_with_tap<F>(&mut self, tap: F) -> SocketAddr
    where
        F: Fn(SocketAddr, &[u8], SocketAddr) + Send + 'static,
    {
        let socket = self.create_socket().await;
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
        addr
    }

    /// Run a proxy server with a supplied config.
    /// Admin is disabled for this method, as the majority of tests will not need it, and it makes it
    /// easier to avoid issues with port collisions.
    pub fn run_server_with_config(&mut self, config: Config) {
        self.run_server_with_builder(Builder::from(Arc::new(config)).disable_admin());
    }

    pub fn run_server_with_builder(&mut self, builder: Builder<PendingValidation>) {
        let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());
        self.server_shutdown_tx.push(Some(shutdown_tx));
        tokio::spawn(async move {
            builder
                .validate()
                .unwrap()
                .build()
                .run(shutdown_rx)
                .await
                .unwrap();
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
pub fn assert_filter_read_no_change<F>(filter: &F)
where
    F: Filter,
{
    let endpoints = vec![Endpoint::new("127.0.0.1:80".parse().unwrap())];
    let from = "127.0.0.1:90".parse().unwrap();
    let contents = "hello".to_string().into_bytes();

    match filter.read(ReadContext::new(
        Endpoints::new(endpoints.clone()).unwrap().into(),
        from,
        contents.clone(),
    )) {
        None => unreachable!("should return a result"),
        Some(response) => {
            assert_eq!(
                endpoints,
                response.endpoints.iter().cloned().collect::<Vec<_>>()
            );
            assert_eq!(contents, response.contents);
        }
    }
}

/// assert that write makes no changes
pub fn assert_write_no_change<F>(filter: &F)
where
    F: Filter,
{
    let endpoint = Endpoint::new("127.0.0.1:90".parse().unwrap());
    let contents = "hello".to_string().into_bytes();

    match filter.write(WriteContext::new(
        &endpoint,
        endpoint.address,
        "127.0.0.1:70".parse().unwrap(),
        contents.clone(),
    )) {
        None => unreachable!("should return a result"),
        Some(response) => assert_eq!(contents, response.contents),
    }
}

pub fn config_with_dummy_endpoint() -> ConfigBuilder {
    ConfigBuilder::empty().with_static(
        vec![],
        vec![Endpoint {
            address: "127.0.0.1:8080".parse().unwrap(),
            ..<_>::default()
        }],
    )
}
/// Creates a dummy endpoint with `id` as a suffix.
pub fn ep(id: u8) -> Endpoint {
    Endpoint {
        address: format!("127.0.0.{}:8080", id).parse().unwrap(),
        ..<_>::default()
    }
}

pub fn new_test_chain(registry: &prometheus::Registry) -> Arc<FilterChain> {
    Arc::new(
        FilterChain::new(
            vec![("TestFilter".into(), Box::new(TestFilter {}))],
            registry,
        )
        .unwrap(),
    )
}

pub fn new_registry(log: &slog::Logger) -> FilterRegistry {
    FilterRegistry::new(FilterSet::default_with(
        log,
        std::array::IntoIter::new([DynFilterFactory::from(Box::from(TestFilterFactory {}))]),
    ))
}

#[cfg(test)]
mod tests {
    use crate::test_utils::TestHelper;

    #[tokio::test]
    async fn test_echo_server() {
        let mut t = TestHelper::default();
        let echo_addr = t.run_echo_server().await;
        let endpoint = t.open_socket_and_recv_single_packet().await;
        let msg = "hello";
        endpoint
            .socket
            .send_to(msg.as_bytes(), &echo_addr)
            .await
            .unwrap();
        assert_eq!(msg, endpoint.packet_rx.await.unwrap());
    }
}
