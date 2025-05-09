/*
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/// On linux spawns a io-uring runtime + thread, everywhere else spawns a regular tokio task.
macro_rules! uring_spawn {
    ($span:expr_2021, $future:expr_2021) => {{
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        use tracing::Instrument as _;

        use tracing::instrument::WithSubscriber as _;

        let fut = async move {
            let _ = tx.send(());
            $future.await
        };

        if let Some(span) = $span {
            tokio::spawn(fut.instrument(span).with_current_subscriber());
        } else {
            tokio::spawn(fut.with_current_subscriber());
        }
        rx
    }};
}

/// Allows creation of spans only when `debug_assertions` are enabled, to avoid
/// hitting the cap of 4096 threads that is unconfigurable in
/// `tracing_subscriber` -> `sharded_slab` for span ids
macro_rules! uring_span {
    ($span:expr_2021) => {{
        cfg_if::cfg_if! {
            if #[cfg(debug_assertions)] {
                Some($span)
            } else {
                Option::<tracing::Span>::None
            }
        }
    }};
}

pub mod cluster;
pub mod endpoint;
pub mod io;
pub mod packet;
pub mod phoenix;

pub(crate) mod error;
pub(crate) mod maxmind_db;
pub mod sessions;

pub use quilkin_xds as xds;
pub use xds::net::TcpListener;

pub use self::{
    cluster::ClusterMap,
    endpoint::{Endpoint, EndpointAddress},
    error::PipelineError,
    io::{Socket, Socket as DualStackLocalSocket, Socket as DualStackEpollSocket, SystemSocket},
};

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };

    use tokio::time::timeout;

    use crate::net::endpoint::address::AddressKind;
    use crate::test::{AddressType, TestHelper, available_addr};

    #[tokio::test]
    async fn dual_stack_socket_reusable() {
        let expected = available_addr(AddressType::Random).await;
        let socket = super::Socket::polling_from_port(expected.port()).unwrap();
        let addr = socket.local_ipv4_addr();

        match expected {
            SocketAddr::V4(_) => assert_eq!(expected, socket.local_ipv4_addr()),
            SocketAddr::V6(_) => assert_eq!(expected, socket.local_ipv6_addr()),
        }

        assert_eq!(expected.port(), socket.local_ipv4_addr().port());
        assert_eq!(expected.port(), socket.local_ipv6_addr().port());

        // should be able to do it a second time, since we are reusing the address.
        let socket = super::Socket::polling_from_port(expected.port()).unwrap();

        match expected {
            SocketAddr::V4(_) => assert_eq!(expected, socket.local_ipv4_addr()),
            SocketAddr::V6(_) => assert_eq!(expected, socket.local_ipv6_addr()),
        }
        assert_eq!(addr.port(), socket.local_ipv4_addr().port());
        assert_eq!(addr.port(), socket.local_ipv6_addr().port());
    }

    #[tokio::test]
    #[cfg_attr(target_os = "macos", ignore)]
    async fn dual_stack_socket() {
        // Since the TestHelper uses the DualStackSocket, we can use it to test ourselves.
        let mut t = TestHelper::default();

        let echo_addr = t.run_echo_server(AddressType::Random).await;
        let (mut rx, socket) = t.open_socket_and_recv_multiple_packets().await;

        let msg = "hello";
        let addr = echo_addr.to_socket_addr().unwrap();

        socket.send_to(msg.as_bytes(), addr).await.unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("should not timeout")
                .unwrap()
        );

        // try again, but from the opposite type of IP Address
        // Proof that a dual stack ipv6 socket can send to both ipv6 and ipv4.
        let ipv4_echo_addr = (Ipv4Addr::UNSPECIFIED, echo_addr.port).into();
        let opp_addr: SocketAddr = match echo_addr.host {
            AddressKind::Ip(ip) => match ip {
                IpAddr::V4(_) => (Ipv6Addr::UNSPECIFIED, echo_addr.port).into(),
                IpAddr::V6(_) => ipv4_echo_addr,
            },
            // we're not testing this, since DNS resolves to IP.
            AddressKind::Name(_) => unreachable!(),
        };

        socket.send_to(msg.as_bytes(), opp_addr).await.unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("should not timeout")
                .unwrap()
        );

        // Since all other sockets are actual ipv6 sockets, let's force a test with a real ipv4 socket sending to our dual
        // stack socket.
        let (mut rx, socket) = t.open_ipv4_socket_and_recv_multiple_packets().await;
        socket
            .send_to(msg.as_bytes(), ipv4_echo_addr)
            .await
            .unwrap();
        assert_eq!(
            msg,
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("should not timeout")
                .unwrap()
        );
    }
}
