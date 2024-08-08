use eyre::Context as _;

impl super::DownstreamReceiveWorkerConfig {
    pub async fn spawn(
        self,
        shutdown: crate::ShutdownRx,
    ) -> eyre::Result<tokio::sync::oneshot::Receiver<()>> {
        use crate::components::proxy::io_uring_shared;

        let Self {
            worker_id,
            upstream_receiver,
            port,
            config,
            sessions,
            error_sender,
            buffer_pool,
        } = self;

        let socket =
            crate::net::DualStackLocalSocket::new(port).context("failed to bind socket")?;

        let io_loop = io_uring_shared::IoUringLoop::new(2000, socket)?;
        io_loop.spawn(
            format!("packet-router-{worker_id}"),
            io_uring_shared::PacketProcessorCtx::Router {
                config,
                sessions,
                error_sender,
                upstream_receiver,
                worker_id,
            },
            buffer_pool,
            shutdown,
        )
    }
}
