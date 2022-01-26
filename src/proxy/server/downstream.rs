use prometheus::HistogramTimer;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;
use tracing::Instrument;

use crate::{
    cluster::cluster_manager::SharedClusterManager,
    endpoint::{Endpoint, EndpointAddress},
    filters::{manager::SharedFilterManager, Filter, ReadContext},
    proxy::sessions::{
        metrics::Metrics as SessionMetrics, session_manager::SessionManager, Session, SessionArgs,
        SessionKey, UpstreamPacket,
    },
};

use super::metrics::Metrics as ProxyMetrics;

/// Packet received from local port
#[derive(Debug)]
pub(crate) struct DownstreamPacket {
    pub source: EndpointAddress,
    pub contents: Vec<u8>,
    pub timer: HistogramTimer,
}

/// Represents the required arguments to run a worker task that
/// processes packets received downstream.
pub(crate) struct DownstreamReceiveWorker {
    /// ID of the worker.
    pub worker_id: usize,
    /// Channel from which the worker picks up the downstream packets.
    pub packet_rx: mpsc::Receiver<DownstreamPacket>,
    /// Configuration required to process a received downstream packet.
    pub processor: DownstreamReceiveProcessor,
    /// The worker task exits when a value is received from this shutdown channel.
    pub shutdown_rx: watch::Receiver<()>,
}

impl DownstreamReceiveWorker {
    // For each worker config provided, spawn a background task that sits in a
    // loop, receiving packets from a queue and processing them through
    // the filter chain.
    #[tracing::instrument(skip_all, fields(worker_id))]
    pub async fn run(self) {
        let Self {
            worker_id,
            mut packet_rx,
            mut shutdown_rx,
            processor,
        } = self;

        loop {
            tokio::select! {
                packet = packet_rx.recv().instrument(tracing::trace_span!("Received downstream packet")) => {
                    match packet {
                        Some(packet) => processor.process_downstream_received_packet(packet).await,
                        None => {
                            tracing::debug!(id = worker_id, "work sender channel was closed.");
                            return;
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    tracing::debug!(id = worker_id, "received shutdown signal.");
                    return;
                }
            }
        }
    }
}

/// Contains arguments to process a received downstream packet, through the
/// filter chain and session pipeline.
pub(crate) struct DownstreamReceiveProcessor {
    pub proxy_metrics: ProxyMetrics,
    pub session_metrics: SessionMetrics,
    pub cluster_manager: SharedClusterManager,
    pub filter_manager: SharedFilterManager,
    pub session_manager: SessionManager,
    pub session_ttl: Duration,
    pub send_packets: mpsc::Sender<UpstreamPacket>,
}

impl DownstreamReceiveProcessor {
    /// Processes a packet by running it through the filter chain.
    #[tracing::instrument(skip_all)]
    async fn process_downstream_received_packet(&self, packet: DownstreamPacket) {
        let endpoints = match self.cluster_manager.read().get_all_endpoints() {
            Some(endpoints) => endpoints,
            None => {
                self.proxy_metrics.packets_dropped_no_endpoints.inc();
                return;
            }
        };

        let filter_chain = {
            let filter_manager_guard = self.filter_manager.read();
            filter_manager_guard.get_filter_chain()
        };
        let result = filter_chain.read(ReadContext::new(
            endpoints,
            packet.source.clone(),
            packet.contents,
        ));

        if let Some(response) = result {
            for endpoint in response.endpoints.iter() {
                self.session_send_packet(&response.contents, packet.source.clone(), endpoint)
                    .await;
            }
        }
        packet.timer.stop_and_record();
    }

    /// Send a packet received from `recv_addr` to an endpoint.
    #[tracing::instrument(level = "trace", skip_all, fields(%recv_addr, %endpoint.address))]
    async fn session_send_packet(
        &self,
        packet: &[u8],
        recv_addr: EndpointAddress,
        endpoint: &Endpoint,
    ) {
        let session_key = SessionKey {
            source: recv_addr,
            dest: endpoint.address.clone(),
        };

        // Grab a read lock and find the session.
        let guard = self.session_manager.get_sessions().await;
        if let Some(session) = guard.get(&session_key) {
            // If it exists then send the packet, we're done.
            Self::session_send_packet_helper(session, packet, self.session_ttl).await
        } else {
            // If it does not exist, grab a write lock so that we can create it.
            //
            // NOTE: We must drop the lock guard to release the lock before
            // trying to acquire a write lock since these lock aren't reentrant,
            // otherwise we will deadlock with our self.
            drop(guard);

            // Grab a write lock.
            let mut guard = self.session_manager.get_sessions_mut().await;

            // Although we have the write lock now, check whether some other thread
            // managed to create the session in-between our dropping the read
            // lock and grabbing the write lock.
            if let Some(session) = guard.get(&session_key) {
                // If the session now exists then we have less work to do,
                // simply send the packet.
                Self::session_send_packet_helper(session, packet, self.session_ttl).await;
            } else {
                // Otherwise, create the session and insert into the map.
                let session_args = SessionArgs {
                    metrics: self.session_metrics.clone(),
                    proxy_metrics: self.proxy_metrics.clone(),
                    filter_manager: self.filter_manager.clone(),
                    source: session_key.source.clone(),
                    dest: endpoint.clone(),
                    sender: self.send_packets.clone(),
                    ttl: self.session_ttl,
                };
                match session_args.into_session().await {
                    Ok(session) => {
                        // Insert the session into the map and release the write lock
                        // immediately since we don't want to block other threads while we send
                        // the packet. Instead, re-acquire a read lock and send the packet.
                        guard.insert(session.key(), session);

                        // Release the write lock.
                        drop(guard);

                        // Grab a read lock to send the packet.
                        let guard = self.session_manager.get_sessions().await;
                        if let Some(session) = guard.get(&session_key) {
                            Self::session_send_packet_helper(session, packet, self.session_ttl)
                                .await;
                        } else {
                            tracing::warn!(
                                key = %format!("({}:{})", session_key.source, session_key.dest),
                                "Could not find session"
                            )
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, "Failed to ensure session exists");
                    }
                }
            }
        }
    }

    // A helper function to push a session's packet on its socket.
    async fn session_send_packet_helper(session: &Session, packet: &[u8], ttl: Duration) {
        match session.send(packet).await {
            Ok(_) => {
                if let Err(error) = session.update_expiration(ttl) {
                    tracing::warn!(%error, "Error updating session expiration")
                }
            }
            Err(error) => tracing::error!(%error, "Error sending packet from session"),
        };
    }
}
