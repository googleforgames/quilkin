mod downstream;
mod upstream;

use std::sync::Arc;

use slog::Logger;
use tokio::{net::UdpSocket, task::JoinHandle};

use crate::{
    cluster::cluster_manager::SharedClusterManager, filters::manager::SharedFilterManager,
    proxy::{ShutdownRx, metrics::ProxyMetrics},
};

use self::{
    downstream::DownstreamDistributor,
    upstream::UpstreamDistributor,
};

pub use self::upstream::{
    DistributorRx, DistributorTx, Error as UpstreamError, Metrics as UpstreamMetrics,
    UpstreamPacket, UpstreamRx, UpstreamTx,
};

pub(crate) struct Pipeline {
    pub(crate) cluster_manager: SharedClusterManager,
    pub(crate) downstream_socket: Arc<UdpSocket>,
    pub(crate) filter_manager: SharedFilterManager,
    pub(crate) log: Logger,
    pub(crate) proxy_metrics: ProxyMetrics,
    pub(crate) upstream_metrics: UpstreamMetrics,
}

impl Pipeline {
    /// Spawns a background task that sits in a loop, receiving packets from the passed in socket.
    /// Each received packet is placed on a queue to be processed by a worker task.
    /// This function also spawns the set of worker tasks responsible for consuming packets
    /// off the aforementioned queue and processing them through the filter chain and session
    /// pipeline.
    pub fn spawn(
        self,
        shutdown_rx: ShutdownRx,
    ) -> (
        JoinHandle<Result<(), UpstreamError>>,
        JoinHandle<Result<(), String>>,
    ) {
        let (distributor_tx, upstream_handle) = UpstreamDistributor {
            log: self.log.clone(),
            metrics: self.upstream_metrics,
            filter_manager: self.filter_manager.clone(),
            downstream_socket: self.downstream_socket.clone(),
        }
        .spawn(shutdown_rx.clone());

        (
            upstream_handle,
            DownstreamDistributor {
                log: self.log,
                socket: self.downstream_socket,
                proxy_metrics: &self.proxy_metrics,
                cluster_manager: &self.cluster_manager,
                filter_manager: &self.filter_manager,
                distributor_tx,
            }
            .spawn(shutdown_rx),
        )
    }
}
