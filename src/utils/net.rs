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

use crate::Result;
use socket2::{Protocol, Socket, Type};
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

/// returns a UdpSocket with address and port reuse.
pub fn socket_with_reuse(addr: SocketAddr) -> Result<UdpSocket> {
    let sock = Socket::new(
        match addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    enable_reuse(&sock)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;

    UdpSocket::from_std(sock.into()).map_err(|error| eyre::eyre!(error))
}

#[cfg(not(target_family = "windows"))]
fn enable_reuse(sock: &Socket) -> io::Result<()> {
    sock.set_reuse_port(true)?;
    Ok(())
}

#[cfg(target_family = "windows")]
fn enable_reuse(sock: &Socket) -> io::Result<()> {
    sock.set_reuse_address(true)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::test_utils::available_addr;

    #[tokio::test]
    async fn socket_with_reuse() {
        let expected = available_addr().await;
        let socket = super::socket_with_reuse(expected).unwrap();
        let addr = socket.local_addr().unwrap();

        assert_eq!(expected, socket.local_addr().unwrap());

        // should be able to do it a second time, since we are reusing the address.
        let socket = super::socket_with_reuse(expected).unwrap();
        let addr2 = socket.local_addr().unwrap();
        assert_eq!(addr, addr2);
    }
}
