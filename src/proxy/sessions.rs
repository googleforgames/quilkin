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

use std::{net::SocketAddr, sync::Arc};

use tokio::{
    net::UdpSocket,
    select,
    sync::{watch, OnceCell},
    time::Instant,
};

use crate::{
    endpoint::{Endpoint, EndpointAddress},
    filters::{Filter, WriteContext},
    maxmind_db::IpNetEntry,
    utils::{net::DualStackLocalSocket, Loggable},
};

pub(crate) mod metrics;

pub type SessionMap = crate::ttl_map::TtlMap<SessionKey, Session>;

/// Session encapsulates a UDP stream session
pub struct Session {
    config: Arc<crate::Config>,
    /// created_at is time at which the session was created
    created_at: Instant,
    /// socket that sends and receives from and to the endpoint address
    upstream_socket: Arc<OnceCell<Arc<UdpSocket>>>,
    /// dest is where to send data to
    dest: Endpoint,
    /// address of original sender
    source: EndpointAddress,
    /// a channel to broadcast on if we are shutting down this Session
    shutdown_tx: watch::Sender<()>,
    /// The ASN information.
    asn_info: Option<IpNetEntry>,
}

// A (source, destination) address pair that uniquely identifies a session.
#[derive(Clone, Eq, Hash, PartialEq, Debug, PartialOrd, Ord)]
pub struct SessionKey {
    pub source: EndpointAddress,
    pub dest: EndpointAddress,
}

impl From<(EndpointAddress, EndpointAddress)> for SessionKey {
    fn from((source, dest): (EndpointAddress, EndpointAddress)) -> Self {
        SessionKey { source, dest }
    }
}

/// ReceivedPacketContext contains state needed to process a received packet.
struct ReceivedPacketContext<'a> {
    packet: &'a [u8],
    config: Arc<crate::Config>,
    endpoint: &'a Endpoint,
    source: EndpointAddress,
    dest: EndpointAddress,
}

impl Session {
    /// internal constructor for a Session from SessionArgs
    #[tracing::instrument(skip_all)]
    pub fn new(
        config: Arc<crate::Config>,
        source: EndpointAddress,
        downstream_socket: Arc<DualStackLocalSocket>,
        dest: Endpoint,
        asn_info: Option<IpNetEntry>,
    ) -> Result<Self, super::PipelineError> {
        let (shutdown_tx, shutdown_rx) = watch::channel::<()>(());

        let s = Session {
            config: config.clone(),
            upstream_socket: Arc::new(OnceCell::new()),
            source: source.clone(),
            dest,
            created_at: Instant::now(),
            shutdown_tx,
            asn_info,
        };

        tracing::debug!(source = %s.source, dest = ?s.dest, "Session created");

        self::metrics::total_sessions().inc();
        s.active_session_metric().inc();
        s.run(downstream_socket, shutdown_rx);
        Ok(s)
    }

    fn upstream_socket(
        &self,
    ) -> impl std::future::Future<Output = Result<Arc<UdpSocket>, super::PipelineError>> {
        let upstream_socket = self.upstream_socket.clone();
        let address = self.dest.address.clone();

        async move {
            let connect_addr = address.to_socket_addr().await?;
            let bind_addr: SocketAddr = match connect_addr {
                SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
                SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
            };

            upstream_socket
                .get_or_try_init(|| async {
                    let upstream_socket = UdpSocket::bind(bind_addr).await?;
                    upstream_socket.connect(connect_addr).await?;
                    Ok(Arc::new(upstream_socket))
                })
                .await
                .cloned()
        }
    }

    /// run starts processing receiving upstream udp packets
    /// and sending them back downstream
    fn run(
        &self,
        downstream_socket: Arc<DualStackLocalSocket>,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        let source = self.source.clone();
        let config = self.config.clone();
        let endpoint = self.dest.clone();
        let upstream_socket = self.upstream_socket();
        let asn_info = self.asn_info.clone();

        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            let mut last_received_at = None;
            let upstream_socket = match upstream_socket.await {
                Ok(socket) => socket,
                Err(error) => {
                    tracing::error!(%error, "upstream socket failed to initialise");
                    return;
                }
            };

            loop {
                tracing::debug!(source = %source, dest = ?endpoint, "Awaiting incoming packet");
                let asn_info = asn_info.as_ref();

                select! {
                    received = upstream_socket.recv_from(&mut buf) => {
                        match received {
                            Err(error) => {
                                crate::metrics::errors_total(crate::metrics::WRITE, &error.to_string(), asn_info).inc();
                                tracing::error!(%error, %source, dest = ?endpoint, "Error receiving packet");
                            },
                            Ok((size, recv_addr)) => {
                                let received_at = chrono::Utc::now().timestamp_nanos_opt().unwrap();
                                if let Some(last_received_at) = last_received_at {
                                    crate::metrics::packet_jitter(crate::metrics::WRITE, asn_info).set(received_at - last_received_at);
                                }
                                last_received_at = Some(received_at);

                                crate::metrics::packets_total(crate::metrics::WRITE, asn_info).inc();
                                crate::metrics::bytes_total(crate::metrics::WRITE, asn_info).inc_by(size as u64);

                                let timer = crate::metrics::processing_time(crate::metrics::WRITE).start_timer();
                                let result = Session::process_recv_packet(
                                    &downstream_socket,
                                    ReceivedPacketContext {
                                        config: config.clone(),
                                        packet: &buf[..size],
                                        endpoint: &endpoint,
                                        source: recv_addr.into(),
                                        dest: source.clone(),
                                    }).await;
                                timer.stop_and_record();
                                if let Err(error) = result {
                                    error.log();
                                    let label = format!("proxy::Session::process_recv_packet: {error}");
                                    crate::metrics::packets_dropped_total(
                                        crate::metrics::WRITE,
                                        &label,
                                        asn_info
                                    ).inc();
                                    crate::metrics::errors_total(crate::metrics::WRITE, &label, asn_info).inc();
                                }
                            }
                        };
                    }
                    _ = shutdown_rx.changed() => {
                        tracing::debug!(%source, dest = ?endpoint, "Closing Session");
                        return;
                    }
                };
            }
        });
    }

    fn active_session_metric(&self) -> prometheus::IntGauge {
        metrics::active_sessions(self.asn_info.as_ref())
    }

    /// process_recv_packet processes a packet that is received by this session.
    async fn process_recv_packet(
        downstream_socket: &Arc<DualStackLocalSocket>,
        packet_ctx: ReceivedPacketContext<'_>,
    ) -> Result<usize, Error> {
        let ReceivedPacketContext {
            packet,
            config,
            endpoint,
            source: from,
            dest,
        } = packet_ctx;

        tracing::trace!(%from, dest = %endpoint.address, contents = %crate::utils::base64_encode(packet), "received packet from upstream");

        let mut context = WriteContext::new(
            endpoint.clone(),
            from.clone(),
            dest.clone(),
            packet.to_vec(),
        );

        config.filters.load().write(&mut context).await?;

        let addr = dest.to_socket_addr().await.map_err(Error::ToSocketAddr)?;
        let packet = context.contents.as_ref();
        tracing::trace!(%from, dest = %addr, contents = %crate::utils::base64_encode(packet), "sending packet downstream");
        downstream_socket
            .send_to(packet, &addr)
            .await
            .map_err(Error::SendTo)
    }

    /// Sends a packet to the Session's dest.
    pub fn send<'buf>(
        &self,
        buf: &'buf [u8],
    ) -> impl std::future::Future<Output = Result<usize, super::PipelineError>> + 'buf {
        tracing::trace!(
        dest_address = %self.dest.address,
        contents = %crate::utils::base64_encode(buf),
        "sending packet upstream");

        let socket = self.upstream_socket();
        async move { socket.await?.send(buf).await.map_err(From::from) }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.active_session_metric().dec();
        metrics::duration_secs().observe(self.created_at.elapsed().as_secs() as f64);

        if let Err(error) = self.shutdown_tx.send(()) {
            tracing::warn!(%error, "Error sending session shutdown signal");
        }

        tracing::debug!(source = %self.source, dest_address = %self.dest.address, "Session closed");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to convert endpoint to socket address: {0}")]
    ToSocketAddr(std::io::Error),
    #[error("failed to send packet downstream: {0}")]
    SendTo(std::io::Error),
    #[error("filter {0}")]
    Filter(#[from] crate::filters::FilterError),
}

impl Loggable for Error {
    fn log(&self) {
        match self {
            Self::ToSocketAddr(error) | Self::SendTo(error) => {
                tracing::error!(kind=%error.kind(), "{}", self)
            }
            Self::Filter(_) => {
                tracing::error!("{}", self);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{str::from_utf8, sync::Arc, time::Duration};

    use tokio::time::timeout;

    use crate::{
        endpoint::{Endpoint, EndpointAddress},
        proxy::sessions::ReceivedPacketContext,
        test_utils::{create_socket, new_test_config, AddressType, TestHelper},
    };

    use super::*;

    #[tokio::test]
    async fn session_send_and_receive() {
        let mut t = TestHelper::default();
        let addr = t.run_echo_server(&AddressType::Random).await;
        let endpoint = Endpoint::new(addr.clone());
        let socket = Arc::new(create_socket().await);
        let msg = "hello";

        let sess =
            Session::new(<_>::default(), addr.clone(), socket.clone(), endpoint, None).unwrap();

        sess.upstream_socket()
            .await
            .unwrap()
            .send(msg.as_bytes())
            .await
            .unwrap();

        let mut buf = vec![0; 1024];
        let (size, recv_addr) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let packet = &buf[..size];
        assert_eq!(msg, from_utf8(packet).unwrap());
        assert_eq!(addr.port(), recv_addr.port());
    }

    #[tokio::test]
    async fn process_recv_packet() {
        crate::test_utils::load_test_filters();

        let socket = Arc::new(create_socket().await);
        let endpoint = Endpoint::new("127.0.1.1:80".parse().unwrap());
        let dest: EndpointAddress = socket.local_ipv4_addr().unwrap().into();

        // first test with no filtering
        let msg = "hello";
        Session::process_recv_packet(
            &socket,
            ReceivedPacketContext {
                config: <_>::default(),
                packet: msg.as_bytes(),
                endpoint: &endpoint,
                source: endpoint.address.clone(),
                dest: dest.clone(),
            },
        )
        .await
        .unwrap();

        let mut buf = vec![0; 1024];
        let (size, recv_addr) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("Should receive a packet")
            .unwrap();
        assert_eq!(msg, from_utf8(&buf[..size]).unwrap());
        assert_eq!(dest.port(), recv_addr.port());

        // add filter
        let config = Arc::new(new_test_config());
        Session::process_recv_packet(
            &socket,
            ReceivedPacketContext {
                config,
                packet: msg.as_bytes(),
                endpoint: &endpoint,
                source: endpoint.address.clone(),
                dest: dest.clone(),
            },
        )
        .await
        .unwrap();

        let (size, recv_addr) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("Should receive a packet")
            .unwrap();
        assert_eq!(
            format!("{}:our:{}:{}", msg, endpoint.address, dest),
            from_utf8(&buf[..size]).unwrap()
        );
        assert_eq!(dest.port(), recv_addr.port());
    }
}
