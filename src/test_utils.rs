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

#[cfg(test)]
pub mod test {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::str::from_utf8;

    use slog::{o, Drain, Logger};
    use slog_term::{FullFormat, PlainSyncDecorator};
    use tokio::net::udp::RecvHalf;
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;

    // logger returns a standard out, non structured terminal logger, suitable for using in tests,
    // since it's more human readable.
    pub fn logger() -> Logger {
        let plain = PlainSyncDecorator::new(std::io::stdout());
        let drain = FullFormat::new(plain).build().fuse();
        Logger::root(drain, o!())
    }

    /// assert_recv_udp asserts that the returned SockerAddr received a UDP packet
    /// with the contents of "hello"
    /// call wait.await.unwrap() to see if the message was received
    pub async fn assert_recv_udp() -> (SocketAddr, oneshot::Receiver<()>) {
        let socket = ephemeral_socket().await;
        let local_addr = socket.local_addr().unwrap();
        let (recv, _) = socket.split();
        let (done, wait) = oneshot::channel::<()>();
        recv_socket_done(recv, done);
        (local_addr, wait)
    }

    /// ephemeral_socket provides a socket bound to an ephemeral port
    pub async fn ephemeral_socket() -> UdpSocket {
        let addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
        UdpSocket::bind(addr).await.unwrap()
    }

    /// recv_socket_done will send a value to done when receiving the "hello" UDP packet.
    pub fn recv_socket_done(mut recv: RecvHalf, done: oneshot::Sender<()>) {
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];
            let size = recv.recv(&mut buf).await.unwrap();
            assert_eq!("hello", from_utf8(&buf[..size]).unwrap());
            done.send(()).unwrap();
        });
    }
}
