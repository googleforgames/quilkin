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

/// Common utilities for testing
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::from_utf8;
use std::sync::Arc;

use slog::{o, warn, Drain, Logger};
use slog_term::{FullFormat, PlainSyncDecorator};
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};

use crate::config::{Config, EndPoint};
use crate::extensions::{
    default_registry, CreateFilterArgs, DownstreamContext, DownstreamResponse, Error, Filter,
    FilterFactory, FilterRegistry, UpstreamContext, UpstreamResponse,
};
use crate::proxy::{Builder, Metrics};

// noop_endpoint returns an endpoint for data that should go nowhere.
pub fn noop_endpoint() -> EndPoint {
    EndPoint {
        name: "noop".to_string(),
        address: "127.0.0.1:10".parse().unwrap(),
        connection_ids: vec![],
    }
}

pub struct TestFilterFactory {}
impl FilterFactory for TestFilterFactory {
    fn name(&self) -> String {
        "TestFilter".to_string()
    }

    fn create_filter(&self, _: CreateFilterArgs) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(TestFilter {}))
    }
}

// TestFilter is useful for testing that commands are executing filters appropriately.
pub struct TestFilter {}

impl Filter for TestFilter {
    fn on_downstream_receive(&self, mut ctx: DownstreamContext) -> Option<DownstreamResponse> {
        // we're going to add an extra endpoint, so we can test for the change,
        // but also so we don't break any tests are expecting traffic at the supplied
        // address and port
        ctx.endpoints.push(noop_endpoint());

        ctx.contents
            .append(&mut format!(":odr:{}", ctx.from).into_bytes());
        Some(ctx.into())
    }

    fn on_upstream_receive(&self, mut ctx: UpstreamContext) -> Option<UpstreamResponse> {
        ctx.contents.append(
            &mut format!(":our:{}:{}:{}", ctx.endpoint.name, ctx.from, ctx.to).into_bytes(),
        );
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
    server_shutdown_tx: Vec<Option<oneshot::Sender<()>>>,
}

/// Returned from [creating a socket](TestHelper::open_socket_and_recv_single_packet)
pub struct OpenSocketRecvPacket {
    /// The local address that the opened socket is bound to.
    pub addr: SocketAddr,
    /// The sender side, after splitting the opened socket.
    pub send: SendHalf,
    /// A channel on which the received packet will be forwarded.
    pub packet_rx: oneshot::Receiver<String>,
}

/// Returned from [creating a socket](TestHelper::create_and_split_socket)
pub struct SplitSocket {
    /// The local address that the opened socket is bound to.
    pub addr: SocketAddr,
    /// The receiver side, after splitting the opened socket.
    pub recv: RecvHalf,
    /// The sender side, after splitting the opened socket.
    pub send: SendHalf,
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
                        "failed to send server shutdown over channel: {:?}", err
                    )
                })
                .ok();
        }

        if let Some((shutdown_tx, _)) = self.shutdown_ch.take() {
            shutdown_tx.broadcast(()).unwrap();
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
    /// Creates a [`Server`] and runs it. The server is shutdown once `self`
    /// goes out of scope.
    pub fn run_server(&mut self, config: Config) {
        self.run_server_with_filter_registry(config, default_registry(&self.log))
    }

    pub fn run_server_with_filter_registry(
        &mut self,
        config: Config,
        filter_registry: FilterRegistry,
    ) {
        self.run_server_with_arguments(config, filter_registry, Metrics::default())
    }

    pub fn run_server_with_metrics(&mut self, config: Config, metrics: Metrics) {
        self.run_server_with_arguments(config, default_registry(&self.log), metrics)
    }

    /// Opens a new socket bound to an ephemeral port
    pub async fn create_socket(&self) -> UdpSocket {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        UdpSocket::bind(addr).await.unwrap()
    }

    /// Helper function to opens a new socket and split it immediately.
    pub async fn create_and_split_socket(&self) -> SplitSocket {
        let socket = self.create_socket().await;
        let addr = socket.local_addr().unwrap();
        let (recv, send) = socket.split();
        SplitSocket { addr, recv, send }
    }

    /// Opens a socket, listening for a packet. Once a packet is received, it
    /// is forwarded over the returned channel.
    pub async fn open_socket_and_recv_single_packet(&self) -> OpenSocketRecvPacket {
        let socket = self.create_socket().await;
        let addr = socket.local_addr().unwrap();
        let (mut recv, send) = socket.split();
        let (packet_tx, packet_rx) = oneshot::channel::<String>();
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let size = recv.recv(&mut buf).await.unwrap();
            packet_tx
                .send(from_utf8(&buf[..size]).unwrap().to_string())
                .unwrap();
        });
        OpenSocketRecvPacket {
            addr,
            send,
            packet_rx,
        }
    }

    /// Opens a socket, listening for packets. Received packets are forwarded over the
    /// returned channel.
    pub async fn open_socket_and_recv_multiple_packets(
        &mut self,
    ) -> (mpsc::Receiver<String>, SendHalf) {
        let (mut packet_tx, packet_rx) = mpsc::channel::<String>(10);
        let (mut socket_recv, socket_send) = self.create_socket().await.split();
        let log = self.log.clone();
        let mut shutdown_rx = self.get_shutdown_subscriber().await;
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
                    _ = shutdown_rx.recv() => {
                        return;
                    }
                }
            }
        });
        (packet_rx, socket_send)
    }

    /// Runs a simple UDP server that echos back payloads.
    /// Returns the server's address.
    pub async fn run_echo_server(&mut self) -> SocketAddr {
        let mut socket = self.create_socket().await;
        let addr = socket.local_addr().unwrap();
        let mut shutdown = self.get_shutdown_subscriber().await;
        tokio::spawn(async move {
            loop {
                let mut buf = vec![0; 1024];
                tokio::select! {
                    recvd = socket.recv_from(&mut buf) => {
                        let (size, sender) = recvd.unwrap();
                        socket.send_to(&buf[..size], sender).await.unwrap();
                    },
                    _ = shutdown.recv() => {
                        return;
                    }
                }
            }
        });
        addr
    }

    /// Create and run a server.
    fn run_server_with_arguments(
        &mut self,
        config: Config,
        filter_registry: FilterRegistry,
        metrics: Metrics,
    ) {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        self.server_shutdown_tx.push(Some(shutdown_tx));
        tokio::spawn(async move {
            Builder::from(Arc::new(config))
                .with_filter_registry(filter_registry)
                .with_metrics(metrics)
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
                let mut ch = watch::channel(());
                // Remove the init value from the channel so that we can later
                // shutdown as soon as we receive any value from the channel.
                let _ = ch.1.recv().await;
                let recv = ch.1.clone();
                self.shutdown_ch = Some(ch);
                recv
            }
        }
    }
    // =======
    // // run_proxy creates a instance of the Server proxy and runs it, returning a cancel function
    // pub fn run_proxy(registry: FilterRegistry, config: Config) -> Box<dyn FnOnce()> {
    //     run_proxy_with_metrics(registry, config, Metrics::default())
    // }
    //
    // // run_proxy_with_metrics creates a instance of the Server proxy and
    // // runs it, returning a cancel function
    // pub fn run_proxy_with_metrics(
    //     registry: FilterRegistry,
    //     config: Config,
    //     metrics: Metrics,
    // ) -> Box<dyn FnOnce()> {
    //     let (close, stop) = oneshot::channel::<()>();
    //     let proxy = Builder::from(Arc::new(config))
    //         .with_filter_registry(registry)
    //         .with_metrics(metrics)
    //         .validate()
    //         .unwrap()
    //         .build();
    //     // run the proxy
    //     tokio::spawn(async move {
    //         proxy.run(stop).await.unwrap();
    //     });
    //
    //     Box::new(|| close.send(()).unwrap())
    // >>>>>>> master
}

/// assert that on_downstream_receive makes no changes
pub fn assert_filter_on_downstream_receive_no_change<F>(filter: &F)
where
    F: Filter,
{
    let endpoints = vec![EndPoint {
        name: "e1".into(),
        address: "127.0.0.1:80".parse().unwrap(),
        connection_ids: vec![],
    }];
    let from = "127.0.0.1:90".parse().unwrap();
    let contents = "hello".to_string().into_bytes();

    match filter.on_downstream_receive(DownstreamContext::new(
        endpoints.clone(),
        from,
        contents.clone(),
    )) {
        None => unreachable!("should return a result"),
        Some(response) => {
            assert_eq!(endpoints, response.endpoints);
            assert_eq!(contents, response.contents);
        }
    }
}

/// assert that on_upstream_receive makes no changes
pub fn assert_filter_on_upstream_receive_no_change<F>(filter: &F)
where
    F: Filter,
{
    let endpoint = EndPoint {
        name: "e1".into(),
        address: "127.0.0.1:90".parse().unwrap(),
        connection_ids: vec![],
    };
    let contents = "hello".to_string().into_bytes();

    match filter.on_upstream_receive(UpstreamContext::new(
        &endpoint,
        endpoint.address,
        "127.0.0.1:70".parse().unwrap(),
        contents.clone(),
    )) {
        None => unreachable!("should return a result"),
        Some(response) => assert_eq!(contents, response.contents),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils::TestHelper;

    #[tokio::test]
    async fn test_echo_server() {
        let mut t = TestHelper::default();
        let echo_addr = t.run_echo_server().await;
        let mut endpoint = t.open_socket_and_recv_single_packet().await;
        let msg = "hello";
        endpoint
            .send
            .send_to(msg.as_bytes(), &echo_addr)
            .await
            .unwrap();
        assert_eq!(msg, endpoint.packet_rx.await.unwrap());
    }
}
