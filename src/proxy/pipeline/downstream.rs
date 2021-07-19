use std::{net::SocketAddr, sync::Arc};

use slog::{debug, error, trace, Logger};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, watch},
};

use crate::{
    cluster::cluster_manager::SharedClusterManager,
    filters::{manager::SharedFilterManager, Filter, ReadContext},
    proxy::{
        pipeline::{DistributorTx, UpstreamPacket},
        ProxyMetrics,
    },
    utils::debug,
};

pub(crate) struct DownstreamDistributor<'spawn> {
    pub(crate) log: Logger,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) distributor_tx: DistributorTx,
    pub(crate) proxy_metrics: &'spawn ProxyMetrics,
    pub(crate) cluster_manager: &'spawn SharedClusterManager,
    pub(crate) filter_manager: &'spawn SharedFilterManager,
}

impl DownstreamDistributor<'_> {
    /// Start the background task to receive downstream packets from the socket
    /// and place them onto the worker tasks' queue for processing.
    pub fn spawn(
        self,
        shutdown_rx: watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<Result<(), String>> {
        let Self {
            log,
            socket,
            distributor_tx,
            proxy_metrics,
            cluster_manager,
            filter_manager,
        } = self;

        let num_workers = num_cpus::get();
        let mut senders: Vec<_> = (0..num_workers)
            .map(|id| {
                let (downstream_tx, downstream_rx) = mpsc::channel(num_workers);

                Downstream {
                    log: log.clone(),
                    proxy_metrics: proxy_metrics.clone(),
                    cluster_manager: cluster_manager.clone(),
                    filter_manager: filter_manager.clone(),
                    distributor_tx: distributor_tx.clone(),
                }
                .spawn(id, downstream_rx, shutdown_rx.clone());

                downstream_tx
            })
            .collect();

        tokio::spawn(async move {
            // Index to round-robin over workers to process packets.
            let mut next_worker = 0;
            let num_workers = num_workers;

            // Initialize a buffer for the UDP packet. We use the maximum size of a UDP
            // packet, which is the maximum value of 16 a bit integer.
            let mut buf = vec![0; 1 << 16];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, recv_addr)) => {
                        let packet_tx = &mut senders[next_worker % num_workers];
                        next_worker += 1;

                        if packet_tx
                            .send(UpstreamPacket::new(recv_addr, (&buf[..size]).to_vec()))
                            .await
                            .is_err()
                        {
                            // We cannot recover from this error since
                            // it implies that the receiver has been dropped.
                            panic!("Failed to send received packet over channel to worker");
                        }
                    }
                    err => {
                        // Socket error, we cannot recover from this so return an error instead.
                        error!(log, "Error processing receive socket"; "error" => #?err);
                        return Err(format!("error processing receive socket: {:?}", err));
                    }
                }
            }
        })
    }
}

/// Contains arguments to process a received downstream packet, through the
/// filter chain and session pipeline.
pub(crate) struct Downstream {
    pub(crate) cluster_manager: SharedClusterManager,
    pub(crate) filter_manager: SharedFilterManager,
    pub(crate) log: Logger,
    pub(crate) proxy_metrics: ProxyMetrics,
    pub(crate) distributor_tx: DistributorTx,
}

impl Downstream {
    pub fn spawn(
        self,
        worker_id: usize,
        mut downstream_rx: mpsc::Receiver<UpstreamPacket>,
        mut shutdown_rx: watch::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let log = self.log.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    packet = downstream_rx.recv() => {
                        match packet {
                            Some(UpstreamPacket { dest, contents }) => self.process_packet(dest, contents).await,
                            None => {
                                debug!(log, "Worker-{} exiting: upstream channel was closed.", worker_id);
                                return;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        debug!(log, "Worker-{} exiting: received shutdown signal.", worker_id);
                        return;
                    }
                }
            }
        })
    }

    /// Processes a packet by running it through the filter chain.
    async fn process_packet(&self, from: SocketAddr, packet: Vec<u8>) {
        trace!(
            self.log,
            "Packet Received";
            "from" => from,
            "contents" => debug::bytes_to_string(&packet),
        );

        let endpoints = match self.cluster_manager.read().get_all_endpoints() {
            Some(endpoints) => endpoints,
            None => {
                self.proxy_metrics.packets_dropped_no_endpoints.inc();
                return;
            }
        };

        let result = {
            let chain = self.filter_manager.read().get_filter_chain();
            chain.read(ReadContext::new(endpoints, from, packet))
        };

        if let Some(response) = result {
            // Broadcast the successful response to all endpoints.
            let broadcasts = std::iter::repeat(response.contents.as_slice())
                .zip(response.endpoints.iter())
                .map(|(contents, endpoint)| {
                    self.distributor_tx
                        .send((from, endpoint.clone(), contents.to_vec()))
                })
                .collect::<Vec<_>>();

            futures::future::join_all(broadcasts)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        }
    }
}
