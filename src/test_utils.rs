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
use tokio::sync::{mpsc, oneshot};

use crate::config::{Config, EndPoint, ValidationError};
use crate::extensions::{Error, Filter, FilterFactory, FilterRegistry};
use crate::server::{Metrics, Server};
use serde_yaml::Value;

pub struct TestFilterFactory {}
impl FilterFactory for TestFilterFactory {
    fn name(&self) -> String {
        "TestFilter".to_string()
    }

    fn validate_config(&self, _: &Value) -> Result<(), ValidationError> {
        Ok(())
    }

    fn create_from_config(&self, _: &Value) -> Result<Box<dyn Filter>, Error> {
        Ok(Box::new(TestFilter {}))
    }
}

// TestFilter is useful for testing that commands are executing filters appropriately.
pub struct TestFilter {}

impl Filter for TestFilter {
    fn on_downstream_receive(
        &self,
        endpoints: &Vec<EndPoint>,
        from: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<(Vec<EndPoint>, Vec<u8>)> {
        let mut c = contents;
        c.append(&mut format!(":odr:{}", from).into_bytes());
        Some((endpoints.clone(), c))
    }

    fn on_upstream_receive(
        &self,
        endpoint: &EndPoint,
        from: SocketAddr,
        to: SocketAddr,
        contents: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut c = contents;
        c.append(&mut format!(":our:{}:{}:{}", endpoint.name, from, to).into_bytes());
        Some(c)
    }
}

// logger returns a standard out, non structured terminal logger, suitable for using in tests,
// since it's more human readable.
pub fn logger() -> Logger {
    let plain = PlainSyncDecorator::new(std::io::stdout());
    let drain = FullFormat::new(plain).build().fuse();
    Logger::root(drain, o!())
}

/// recv_udp waits for a UDP packet to be received on SocketAddr, and sends
/// that value to the oneshot channel so it can be tested.
pub async fn recv_udp() -> (SocketAddr, oneshot::Receiver<String>) {
    let socket = ephemeral_socket().await;
    let local_addr = socket.local_addr().unwrap();
    let (recv, _) = socket.split();
    let (done, wait) = oneshot::channel::<String>();
    recv_udp_done(recv, done);
    (local_addr, wait)
}

/// ephemeral_socket provides a socket bound to an ephemeral port
pub async fn ephemeral_socket() -> UdpSocket {
    let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
    UdpSocket::bind(addr).await.unwrap()
}

/// recv_udp_done will send the String value of the receiving UDP packet to the passed in oneshot channel.
pub fn recv_udp_done(mut recv: RecvHalf, done: oneshot::Sender<String>) {
    tokio::spawn(async move {
        let mut buf = vec![0; 1024];
        let size = recv.recv(&mut buf).await.unwrap();
        done.send(from_utf8(&buf[..size]).unwrap().to_string())
            .unwrap();
    });
}

// recv_multiple_packets enables you to send multiple packets through SendHalf
// and will return any received packets back to the Receiver.
pub async fn recv_multiple_packets(logger: &Logger) -> (mpsc::Receiver<String>, SendHalf) {
    let (mut send_chan, recv_chan) = mpsc::channel::<String>(10);
    let (mut recv, send) = ephemeral_socket().await.split();
    // a channel, so we can wait for packets coming back.
    let logger = logger.clone();
    tokio::spawn(async move {
        let mut buf = vec![0; 1024];
        loop {
            let (size, _) = recv.recv_from(&mut buf).await.unwrap();
            let str = from_utf8(&buf[..size]).unwrap().to_string();
            match send_chan.send(str).await {
                Ok(_) => {}
                Err(err) => {
                    warn!(logger, "recv_multiple_packets: recv_chan dropped"; "error" => %err);
                    break;
                }
            };
        }
    });
    (recv_chan, send)
}

// echo_server runs a udp echo server, and returns the ephemeral addr
// that it is running on.
pub async fn echo_server() -> SocketAddr {
    let mut socket = ephemeral_socket().await;
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0; 1024];
        let (size, sender) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&buf[..size], sender).await.unwrap();
    });
    addr
}

// run_proxy creates a instance of the Server proxy and runs it, returning a cancel function
pub fn run_proxy(logger: &Logger, registry: FilterRegistry, config: Config) -> Box<dyn FnOnce()> {
    run_proxy_with_metrics(logger, registry, config, Metrics::default())
}

// run_proxy_with_metrics creates a instance of the Server proxy and
// runs it, returning a cancel function
pub fn run_proxy_with_metrics(
    logger: &Logger,
    registry: FilterRegistry,
    config: Config,
    metrics: Metrics,
) -> Box<dyn FnOnce()> {
    let (close, stop) = oneshot::channel::<()>();
    let proxy = Server::new(logger.clone(), registry, metrics);
    // run the proxy
    tokio::spawn(async move {
        proxy.run(Arc::new(config), stop).await.unwrap();
    });

    Box::new(|| close.send(()).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_echo_server() {
        let echo_addr = echo_server().await;
        let (recv, mut send) = ephemeral_socket().await.split();
        let (done, wait) = oneshot::channel::<String>();
        let msg = "hello";
        recv_udp_done(recv, done);
        send.send_to(msg.as_bytes(), &echo_addr).await.unwrap();
        assert_eq!(msg, wait.await.unwrap());
    }
}
