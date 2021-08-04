mod error;
mod metrics;
mod packet;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use slog::{debug, error, o, trace, warn, Logger};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::JoinHandle,
    time::{Duration, Instant},
};

use crate::{
    cluster::Endpoint,
    filters::{manager::SharedFilterManager, Filter, WriteContext},
    proxy::ShutdownRx,
    utils::debug,
};

pub use self::{error::Error, metrics::Metrics, packet::UpstreamPacket};

type UpstreamMap = std::collections::HashMap<(SocketAddr, SocketAddr), UpstreamTx>;
type Result<T, E = Error> = std::result::Result<T, E>;
pub type UpstreamTx = mpsc::Sender<Vec<u8>>;
pub type UpstreamRx = mpsc::Receiver<Vec<u8>>;
pub type DistributorTx = mpsc::Sender<(SocketAddr, Endpoint, Vec<u8>)>;
pub type DistributorRx = mpsc::Receiver<(SocketAddr, Endpoint, Vec<u8>)>;

const QUEUE_SIZE: usize = 1024;
const UPSTREAM_EXPIRY_INTERVAL: Duration = Duration::from_secs(60);

pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

fn upstream_queue() -> (UpstreamTx, UpstreamRx) {
    mpsc::channel(QUEUE_SIZE)
}

fn distributor_queue() -> (DistributorTx, DistributorRx) {
    mpsc::channel(QUEUE_SIZE)
}

pub(crate) struct UpstreamDistributor {
    pub(crate) log: slog::Logger,
    pub(crate) metrics: Metrics,
    pub(crate) downstream_socket: Arc<UdpSocket>,
    pub(crate) filter_manager: SharedFilterManager,
}

impl UpstreamDistributor {
    pub fn spawn(self, mut shutdown_rx: ShutdownRx) -> (DistributorTx, JoinHandle<Result<()>>) {
        let mut manager = UpstreamMap::new();
        let mut expiry_poll = tokio::time::interval(UPSTREAM_EXPIRY_INTERVAL);
        let (distributor_tx, mut distributor_rx) = distributor_queue();

        let handle = tokio::spawn(async move {
            loop {
                slog::debug!(self.log, "Awaiting incoming packet");
                tokio::select! {
                    received = distributor_rx.recv() => {
                        match received {
                            Some((from, endpoint, contents)) => {
                                self.process(&mut manager, &shutdown_rx, from, endpoint, contents).await?;
                            }
                            None => {
                                debug!(self.log, "Unable to retrieve message from downstream.");
                                return Ok(())
                            }
                        }
                    }
                    _ = expiry_poll.tick() => {
                        slog::info!(self.log, "Pruning Upstreams");
                        manager.retain(|_, v| !v.is_closed());
                    }
                    _ = shutdown_rx.changed() => {
                        slog::debug!(self.log, "Closing Upstream");
                        return Ok(());
                    }
                };
            }
        });

        (distributor_tx, handle)
    }

    async fn process(
        &self,
        manager: &mut UpstreamMap,
        shutdown_rx: &ShutdownRx,
        from: SocketAddr,
        endpoint: Endpoint,
        contents: Vec<u8>,
    ) -> Result<()> {
        use std::collections::hash_map::Entry;
        let new_upstream = || {
            Upstream::new(
                self.log.clone(),
                self.filter_manager.clone(),
                self.metrics.clone(),
                self.downstream_socket.clone(),
                from,
                endpoint.clone(),
            )
        };

        match manager.entry((from, endpoint.address)) {
            Entry::Vacant(entry) => {
                let sender = entry.insert((new_upstream)().await?.spawn(shutdown_rx.clone()));

                sender.send(contents).await.map_err(Error::Sender)?;
            }
            Entry::Occupied(mut entry) => {
                // If we get an error, then the session has expired, so
                // insert a new upstream.
                if let Err(_) = entry.get().send(contents.clone()).await {
                    entry
                        .insert((new_upstream)().await?.spawn(shutdown_rx.clone()))
                        .send(contents)
                        .await
                        .unwrap();
                }
            }
        }

        Ok(())
    }
}

/// Upstream encapsulates a UDP stream session
pub struct Upstream {
    pub(crate) log: Logger,
    /// created_at is time at which the session was created
    pub(crate) created_at: Instant,
    pub(crate) downstream_socket: Arc<UdpSocket>,
    pub(crate) upstream_socket: UdpSocket,
    /// The original source that created the session.
    pub(crate) source_addr: SocketAddr,
    /// The original endpoint where the data comes from.
    pub(crate) endpoint: Endpoint,
    pub(crate) expiration: Arc<AtomicU64>,
    pub(crate) metrics: Metrics,
    pub(crate) ttl: tokio::time::Duration,
    pub(crate) filter_manager: SharedFilterManager,
}

impl Upstream {
    /// new creates a new Upstream, and starts the process of receiving udp sockets
    /// from its ephemeral port from endpoint(s)
    async fn new(
        log: Logger,
        filter_manager: SharedFilterManager,
        metrics: Metrics,
        downstream_socket: Arc<UdpSocket>,
        source_addr: SocketAddr,
        endpoint: Endpoint,
    ) -> Result<Self> {
        let log = log
            .new(o!("source" => "proxy::Upstream", "source" => source_addr, "endpoint_address" => endpoint.address));
        let expiration = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let upstream_socket = {
            let auto_assign = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
            UdpSocket::bind(auto_assign)
                .await
                .map_err(Error::BindUdpSocket)?
        };

        let upstream = Self {
            log,
            source_addr,
            endpoint,
            created_at: tokio::time::Instant::now(),
            expiration,
            metrics,
            ttl: DEFAULT_TTL,
            downstream_socket,
            filter_manager,
            upstream_socket,
        };

        upstream.update_expiration()?;
        debug!(upstream.log, "Upstream created");
        upstream.metrics.sessions_total.inc();
        upstream.metrics.active_sessions.inc();

        Ok(upstream)
    }

    /// run starts processing received udp packets on its UdpSocket
    pub fn spawn(self, mut shutdown_rx: ShutdownRx) -> UpstreamTx {
        let mut expiry_poll = tokio::time::interval(UPSTREAM_EXPIRY_INTERVAL);
        let (upstream_tx, mut upstream_rx) = upstream_queue();

        tokio::spawn(async move {
            let mut buf: Vec<u8> = vec![0; 65535];
            loop {
                tokio::select! {
                    received = upstream_rx.recv() => {
                        match received {
                            None => {
                                todo!()
                            },
                            Some(contents) => self.send(&contents).await,
                        }
                    }
                    received = self.upstream_socket.recv_from(&mut buf) => {
                        match received {
                            Err(err) => {
                                self.metrics.rx_errors_total.inc();
                                error!(self.log, "Error receiving packet"; "error" => %err);
                            },
                            Ok((size, _)) => {
                                self.metrics.rx_bytes_total.inc_by(size as u64);
                                self.metrics.rx_packets_total.inc();
                                self.process_packet(&buf[..size]).await
                            }
                        };
                    }
                    _ = expiry_poll.tick() => {
                        if self.is_expired() {
                            return;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        return;
                    }
                }
            }
        });

        upstream_tx
    }

    async fn process_packet(&self, packet: &[u8]) {
        slog::trace!(self.log, "Received packet"; "from" => self.endpoint.address,
            "endpoint_addr" => &self.endpoint.address,
            "contents" => debug::bytes_to_string(packet));

        if let Err(err) = self.update_expiration() {
            slog::warn!(self.log, "Error updating session expiration"; "error" => %err)
        }

        let filter_chain = {
            let filter_manager_guard = self.filter_manager.read();
            filter_manager_guard.get_filter_chain()
        };

        if let Some(response) = filter_chain.write(WriteContext::new(
            self.endpoint.clone(),
            self.endpoint.address,
            self.source_addr,
            packet.to_vec(),
        )) {
            slog::debug!(
                self.log,
                "Sending packet back to origin";
                "origin" => self.endpoint.address,
                "contents" => debug::bytes_to_string(&response.contents),
            );

            if let Err(err) = self.downstream_socket.send(&response.contents).await {
                slog::error!(self.log, "Error sending packet"; "dest" => %self.source_addr, "error" => %err);
            }
        } else {
            self.metrics.packets_dropped_total.inc();
        }
    }

    /// expiration returns the current expiration Instant value
    pub fn expiration(&self) -> u64 {
        self.expiration.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns whether the upstream session has expired.
    pub fn is_expired(&self) -> bool {
        let now = if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) {
            now.as_secs()
        } else {
            warn!(
                self.log,
                "Failed to get current time when checking upstream"
            );
            return false;
        };

        self.expiration() <= now
    }

    /// update_expiration set the increments the expiration value by the session timeout
    pub fn update_expiration(&self) -> Result<()> {
        Self::do_update_expiration(&self.expiration, self.ttl)
    }

    /// do_update_expiration increments the expiration value by the session timeout (internal)
    fn do_update_expiration(expiration: &Arc<AtomicU64>, ttl: Duration) -> Result<()> {
        let new_expiration_time = SystemTime::now()
            .checked_add(ttl)
            .ok_or_else(|| {
                Error::UpdateSessionExpiration(format!(
                    "checked_add error: expiration ttl {:?} is out of bounds",
                    ttl
                ))
            })?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                Error::UpdateSessionExpiration(
                    "duration_since was called with time later than the current time".into(),
                )
            })?
            .as_secs();

        expiration.store(new_expiration_time, Ordering::Relaxed);

        Ok(())
    }

    /// Sends a packet to the Upstream's dest.
    pub async fn send(&self, buf: &[u8]) {
        trace!(self.log, "Sending packet";
            "endpoint_address" => &self.endpoint.address,
            "contents" => debug::bytes_to_string(buf));

        let result = self
            .do_send(buf)
            .await
            .map(|size| {
                self.metrics.tx_packets_total.inc();
                self.metrics.tx_bytes_total.inc_by(size as u64);
                Some(size)
            })
            .map_err(|err| {
                self.metrics.tx_errors_total.inc();
                Error::SendToDst(err)
            });

        match result {
            Ok(_) => {
                if let Err(err) = self.update_expiration() {
                    warn!(self.log, "Error updating session expiration"; "error" => %err)
                }
            }
            Err(err) => error!(self.log, "Error sending packet from session"; "error" => %err),
        }
    }

    /// Sends `buf` to the session's destination address. On success, returns
    /// the number of bytes written.
    async fn do_send(&self, buf: &[u8]) -> std::result::Result<usize, std::io::Error> {
        self.downstream_socket
            .send_to(buf, &self.endpoint.address)
            .await
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.metrics.active_sessions.dec();
        self.metrics
            .duration_secs
            .observe(self.created_at.elapsed().as_secs() as f64);
        debug!(self.log, "Upstream closed"; "source" => self.source_addr, "endpoint_address" => &self.endpoint.address);
    }
}

#[cfg(test)]
mod tests {
    use std::str::from_utf8;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{Metrics, Upstream, UpstreamPacket};

    use prometheus::Registry;
    use tokio::time::timeout;

    use crate::filters::FilterChain;
    use crate::test_utils::{new_test_chain, TestHelper};

    //use super::ReceivedUpstreamPacketContext;
    use crate::cluster::Endpoint;
    use crate::filters::manager::FilterManager;
    use tokio::{net::UdpSocket, sync::mpsc};

    async fn new_session() -> (Arc<UdpSocket>, Upstream) {
        let t = TestHelper::default();
        let downstream_socket = t.create_socket().await;
        let addr = downstream_socket.local_addr().unwrap();
        let endpoint = Endpoint::from_address(addr);
        let upstream = Upstream::new(
            t.log.clone(),
            FilterManager::fixed(Arc::new(FilterChain::new(vec![], &Registry::default()).unwrap())),
            Metrics::new(&Registry::default()).unwrap(),
            downstream_socket.clone(),
            addr,
            endpoint,
        )
        .await
        .unwrap();

        (downstream_socket, upstream)
    }

    #[tokio::test]
    async fn session_new_metrics() {
        let(_, upstream) = new_session().await;

        assert_eq!(upstream.metrics.sessions_total.get(), 1);
        assert_eq!(upstream.metrics.active_sessions.get(), 1);
    }


    // #[tokio::test]
    // async fn send_to_metrics() {
    //     let t = TestHelper::default();

    //     let (sender, _) = mpsc::channel::<UpstreamPacket>(1);
    //     let endpoint = t.open_socket_and_recv_single_packet().await;
    //     let addr = endpoint.socket.local_addr().unwrap();
    //     let registry = Registry::default();
    //     let session = Upstream::new(
    //         &t.log,
    //         Metrics::new(&registry).unwrap(),
    //         FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
    //         addr,
    //         Endpoint::from_address(addr),
    //         sender,
    //         Duration::from_secs(10),
    //     )
    //     .await
    //     .unwrap();
    //     session.send(b"hello").await.unwrap();
    //     endpoint.packet_rx.await.unwrap();

    //     assert_eq!(session.metrics.tx_bytes_total.get(), 5);
    //     assert_eq!(session.metrics.tx_packets_total.get(), 1);
    // }

    // #[tokio::test]
    // async fn session_drop_metrics() {
    //     let t = TestHelper::default();
    //     let (send_packet, _) = mpsc::channel::<UpstreamPacket>(5);
    //     let endpoint = t.open_socket_and_recv_single_packet().await;
    //     let addr = endpoint.socket.local_addr().unwrap();
    //     let registry = Registry::default();
    //     let session = Upstream::new(
    //         &t.log,
    //         Metrics::new(&registry).unwrap(),
    //         FilterManager::fixed(Arc::new(FilterChain::new(vec![], &registry).unwrap())),
    //         addr,
    //         Endpoint::from_address(addr),
    //         send_packet,
    //         Duration::from_secs(10),
    //     )
    //     .await
    //     .unwrap();

    //     assert_eq!(session.metrics.sessions_total.get(), 1);
    //     assert_eq!(session.metrics.active_sessions.get(), 1);

    //     let metrics = session.metrics.clone();
    //     drop(session);
    //     assert_eq!(metrics.sessions_total.get(), 1);
    //     assert_eq!(metrics.active_sessions.get(), 0);
    // }

    // #[tokio::test]
    // async fn process_recv_packet() -> Result<(), Box<dyn std::error::Error>> {
    //     let t = TestHelper::default();
    //     let registry = Registry::default();

    //     let (_tx, shutdown_rx) = tokio::sync::watch::channel();
    //     let downstream_socket = Arc::new(UdpSocket::bind("0.0.0.0:0")?);
    //     let chain = Arc::new(FilterChain::new(vec![], &registry).unwrap());
    //     let endpoint = Endpoint::from_address("127.0.1.1:80".parse().unwrap());
    //     let dest = "127.0.0.1:88".parse().unwrap();
    //     let upstream_queue = Upstream::new(
    //         t.log,
    //         FilterManager::fixed(chain),
    //         Metrics::new(&Registry::default()).unwrap(),
    //         downstream_socket.clone(),
    //         dest,
    //         endpoint,
    //     )
    //     .spawn(shutdown_rx);

    //     // first test with no filtering
    //     let msg = "hello";
    //     Upstream::process_recv_packet(
    //         &t.log,
    //         &mut sender,
    //         &expiration,
    //         Duration::from_secs(10),
    //         ReceivedUpstreamPacketContext {
    //             packet: msg.as_bytes(),
    //             filter_manager: FilterManager::fixed(chain),
    //             endpoint: &endpoint,
    //             from: endpoint.address,
    //             to: dest,
    //         },
    //     )
    //     .await;

    //     assert!(initial_expiration < expiration.load(Ordering::Relaxed));
    //     let p = timeout(Duration::from_secs(5), receiver.recv())
    //         .await
    //         .expect("Should receive a packet")
    //         .unwrap();
    //     assert_eq!(msg, from_utf8(p.contents.as_slice()).unwrap());
    //     assert_eq!(dest, p.dest);

    //     let expiration = Arc::new(AtomicU64::new(
    //         SystemTime::now()
    //             .duration_since(UNIX_EPOCH)
    //             .unwrap()
    //             .as_secs(),
    //     ));
    //     let initial_expiration = expiration.load(Ordering::Relaxed);
    //     // add filter
    //     let registry = Registry::default();
    //     let chain = new_test_chain(&registry);
    //     Upstream::process_recv_packet(
    //         &t.log,
    //         &Metrics::new(&registry).unwrap(),
    //         &mut sender,
    //         &expiration,
    //         Duration::from_secs(10),
    //         ReceivedUpstreamPacketContext {
    //             filter_manager: FilterManager::fixed(chain),
    //             packet: msg.as_bytes(),
    //             endpoint: &endpoint,
    //             from: endpoint.address,
    //             to: dest,
    //         },
    //     )
    //     .await;

    //     assert!(initial_expiration < expiration.load(Ordering::Relaxed));
    //     let p = timeout(Duration::from_secs(5), receiver.recv())
    //         .await
    //         .expect("Should receive a packet")
    //         .unwrap();
    //     assert_eq!(
    //         format!("{}:our:{}:{}", msg, endpoint.address, dest),
    //         from_utf8(p.contents.as_slice()).unwrap()
    //     );
    //     assert_eq!(dest, p.dest);
    // }
}
