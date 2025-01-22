use std::{future::Future, sync::Arc};

use crate::{components::proxy::SessionPool, config::Config};

#[derive(Debug, clap::Parser)]
#[command(next_help_heading = "Service Options")]
pub struct Service {
    /// Whether to serve mDS requests.
    #[arg(
        long = "service.mds",
        env = "QUILKIN_PUBLISH_MDS",
        default_value_t = false
    )]
    mds_enabled: bool,
    /// The TCP port to listen to serve xDS requests.
    #[clap(
        long = "service.mds.port",
        env = "QUILKIN_PUBLISH_MDS_PORT",
        default_value_t = 7900
    )]
    mds_port: u16,
    /// Whether to serve UDP requests.
    #[arg(
        long = "service.phoenix",
        env = "QUILKIN_PUBLISH_PHOENIX",
        default_value_t = false
    )]
    phoenix_enabled: bool,
    /// The UDP port to listen for UDP packets.
    #[clap(
        long = "service.phoenix.port",
        env = "QUILKIN_PUBLISH_PHOENIX_PORT",
        default_value_t = 7600
    )]
    phoenix_port: u16,
    /// Whether to serve UDP requests.
    #[arg(
        long = "service.qcmp",
        env = "QUILKIN_PUBLISH_QCMP",
        default_value_t = false
    )]
    qcmp_enabled: bool,
    /// The UDP port to listen for UDP packets.
    #[clap(
        long = "service.qcmp.port",
        env = "QUILKIN_PUBLISH_QCMP_PORT",
        default_value_t = 7600
    )]
    qcmp_port: u16,
    /// Whether to serve UDP requests.
    #[arg(
        long = "service.udp",
        env = "QUILKIN_PUBLISH_UDP",
        default_value_t = false
    )]
    udp_enabled: bool,
    /// The UDP port to listen for UDP packets.
    #[clap(
        long = "service.udp.port",
        env = "QUILKIN_PUBLISH_UDP_PORT",
        default_value_t = 7777
    )]
    udp_port: u16,
    #[clap(flatten)]
    pub xdp: XdpOptions,
    /// Amount of UDP workers to run.
    #[clap(long = "service.udp.workers", env = "QUILKIN_PUBLISH_UDP_WORKERS", default_value_t = std::num::NonZeroUsize::new(num_cpus::get()).unwrap())]
    pub udp_workers: std::num::NonZeroUsize,
    /// Whether to serve xDS requests.
    #[arg(
        long = "service.xds",
        env = "QUILKIN_PUBLISH_XDS",
        default_value_t = false
    )]
    xds_enabled: bool,
    /// The TCP port to listen to serve xDS requests.
    #[clap(
        long = "service.xds.port",
        env = "QUILKIN_PUBLISH_XDS_PORT",
        default_value_t = 7800
    )]
    xds_port: u16,
}

impl Default for Service {
    fn default() -> Self {
        Self {
            mds_enabled: <_>::default(),
            mds_port: 7900,
            phoenix_enabled: <_>::default(),
            phoenix_port: 7600,
            qcmp_enabled: <_>::default(),
            qcmp_port: 7600,
            udp_enabled: <_>::default(),
            udp_port: 7777,
            udp_workers: std::num::NonZeroUsize::new(num_cpus::get()).unwrap(),
            xds_enabled: <_>::default(),
            xds_port: 7800,
            xdp: <_>::default(),
        }
    }
}

impl Service {
    /// Enables the UDP service.
    pub fn udp(mut self) -> Self {
        self.udp_enabled = true;
        self
    }

    /// Sets the UDP service port.
    pub fn udp_port(mut self, port: u16) -> Self {
        self.udp_port = port;
        self
    }

    /// Enables the QCMP service.
    pub fn qcmp(mut self) -> Self {
        self.qcmp_enabled = true;
        self
    }

    /// Sets the UDP service port.
    pub fn qcmp_port(mut self, port: u16) -> Self {
        self.qcmp_port = port;
        self
    }

    /// Enables the mDS service.
    pub fn mds(mut self) -> Self {
        self.mds_enabled = true;
        self
    }

    /// Sets the mDS service port.
    pub fn mds_port(mut self, port: u16) -> Self {
        self.mds_port = port;
        self
    }

    /// Enables the Phoenix service.
    pub fn phoenix(mut self) -> Self {
        self.phoenix_enabled = true;
        self
    }

    /// Sets the Phoenix service port.
    pub fn phoenix_port(mut self, port: u16) -> Self {
        self.phoenix_port = port;
        self
    }

    /// Enables the xDS service.
    pub fn xds(mut self) -> Self {
        self.xds_enabled = true;
        self
    }

    /// Sets the xDS service port.
    pub fn xds_port(mut self, port: u16) -> Self {
        self.xds_port = port;
        self
    }

    /// The main entrypoint for listening network servers. When called will
    /// spawn any and all enabled services, if successful returning a future
    /// that can be await to wait on services to be cancelled.
    pub fn spawn_services(
        self,
        config: &Arc<Config>,
        shutdown_rx: &crate::ShutdownRx,
    ) -> crate::Result<tokio::task::JoinHandle<crate::Result<()>>> {
        let shutdown_rx = shutdown_rx.clone();
        let config = config.clone();
        Ok(tokio::spawn(async move {
            let mds_task = self.publish_mds(&config)?;
            let phoenix_task = self.publish_phoenix(&config, &shutdown_rx)?;
            let qcmp_task = self.publish_qcmp(&shutdown_rx)?;
            let (udp_task, finalizer) = self.publish_udp(&config)?;
            let xds_task = self.publish_xds(&config)?;

            let result = tokio::select! {
                result = mds_task => result,
                result = phoenix_task => result,
                result = qcmp_task => result,
                result = udp_task => result,
                result = xds_task => result,
            };

            if let Some(finalizer) = finalizer {
                (finalizer)(shutdown_rx.clone());
            }

            result
        }))
    }

    /// Spawns an QCMP server if enabled, otherwise returns a future which never completes.
    fn publish_phoenix(
        &self,
        config: &Arc<Config>,
        shutdown_rx: &crate::ShutdownRx,
    ) -> crate::Result<impl std::future::Future<Output = crate::Result<()>>> {
        if self.phoenix_enabled {
            let phoenix = crate::net::TcpListener::bind(Some(self.phoenix_port))?;
            crate::net::phoenix::spawn(
                phoenix,
                config.clone(),
                shutdown_rx.clone(),
                crate::net::phoenix::Phoenix::new(crate::codec::qcmp::QcmpMeasurement::new()?),
            )?
        }

        Ok(std::future::pending())
    }

    /// Spawns an QCMP server if enabled, otherwise returns a future which never completes.
    fn publish_qcmp(
        &self,
        shutdown_rx: &crate::ShutdownRx,
    ) -> crate::Result<impl Future<Output = crate::Result<()>>> {
        if self.qcmp_enabled {
            let qcmp = crate::net::raw_socket_with_reuse(self.qcmp_port)?;
            crate::codec::qcmp::spawn(qcmp, shutdown_rx.clone())?;
        }

        Ok(std::future::pending())
    }

    /// Spawns an xDS server if enabled, otherwise returns a future which never completes.
    fn publish_mds(
        &self,
        config: &Arc<Config>,
    ) -> crate::Result<impl Future<Output = crate::Result<()>>> {
        if !self.mds_enabled {
            return Ok(either::Left(std::future::pending()));
        }

        use futures::TryFutureExt as _;

        let listener = crate::net::TcpListener::bind(Some(self.mds_port))?;

        Ok(either::Right(
            tokio::spawn(
                crate::net::xds::server::ControlPlane::from_arc(
                    config.clone(),
                    crate::components::admin::IDLE_REQUEST_INTERVAL,
                )
                .relay_server(listener)?,
            )
            .map_err(From::from)
            .and_then(std::future::ready),
        ))
    }

    /// Spawns an xDS server if enabled, otherwise returns a future which never completes.
    fn publish_xds(
        &self,
        config: &Arc<Config>,
    ) -> crate::Result<impl Future<Output = crate::Result<()>>> {
        if !self.xds_enabled {
            return Ok(either::Left(std::future::pending()));
        }

        use futures::TryFutureExt as _;

        let listener = crate::net::TcpListener::bind(Some(self.xds_port))?;

        Ok(either::Right(
            tokio::spawn(
                crate::net::xds::server::ControlPlane::from_arc(
                    config.clone(),
                    crate::components::admin::IDLE_REQUEST_INTERVAL,
                )
                .management_server(listener)?,
            )
            .map_err(From::from)
            .and_then(std::future::ready),
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn publish_udp(
        &self,
        config: &Arc<crate::config::Config>,
    ) -> eyre::Result<(
        impl Future<Output = crate::Result<()>>,
        Option<Box<dyn FnOnce(crate::ShutdownRx) + Send>>,
    )> {
        if !self.udp_enabled {
            return Ok((either::Left(std::future::pending()), None));
        }

        #[cfg(target_os = "linux")]
        {
            match self.spawn_xdp(config.clone(), self.xdp.force_xdp) {
                Ok(xdp) => return Ok((either::Left(std::future::pending()), Some(xdp))),
                Err(err) => {
                    if self.xdp.force_xdp {
                        return Err(err);
                    }

                    tracing::debug!(
                        ?err,
                        "failed to spawn XDP I/O loop, falling back to io-uring"
                    );
                }
            }
        }

        self.spawn_user_space_router(config.clone())
            .map(|(fut, func)| (either::Right(fut), Some(func)))
    }

    /// Launches the user space implementation of the packet router using
    /// sockets. This implementation uses a pool of buffers and sockets to
    /// manage UDP sessions and sockets. On Linux this will use io-uring, where
    /// as it will use epoll interfaces on non-Linux platforms.
    #[allow(clippy::type_complexity)]
    pub fn spawn_user_space_router(
        &self,
        config: Arc<crate::config::Config>,
    ) -> crate::Result<(
        impl Future<Output = crate::Result<()>>,
        Box<dyn FnOnce(crate::ShutdownRx) + Send>,
    )> {
        let socket = crate::net::raw_socket_with_reuse(self.udp_port)?;
        let workers = self.udp_workers.get();
        let buffer_pool = Arc::new(crate::collections::BufferPool::new(workers, 2 * 1024));

        let mut worker_sends = Vec::with_capacity(workers);
        let mut session_sends = Vec::with_capacity(workers);
        for _ in 0..workers {
            let queue = crate::net::queue(15)?;
            session_sends.push(queue.0.clone());
            worker_sends.push(queue);
        }

        let sessions = SessionPool::new(config.clone(), session_sends, buffer_pool.clone());

        crate::components::proxy::packet_router::spawn_receivers(
            config,
            socket,
            worker_sends,
            &sessions,
            buffer_pool,
        )?;

        Ok((
            std::future::pending(),
            Box::from(move |shutdown_rx: crate::ShutdownRx| {
                sessions.shutdown(*shutdown_rx.borrow() == crate::ShutdownKind::Normal);
            }),
        ))
    }

    #[cfg(target_os = "linux")]
    fn spawn_xdp(
        &self,
        config: Arc<crate::config::Config>,
        force_xdp: bool,
    ) -> eyre::Result<Box<dyn FnOnce(crate::ShutdownRx) + Send>> {
        use crate::net::xdp;
        use eyre::Context as _;

        // TODO: remove this once it's been more stabilized
        if !force_xdp {
            eyre::bail!("XDP currently disabled by default");
        }

        let workers = xdp::setup_xdp_io(xdp::XdpConfig {
            nic: self
                .xdp
                .network_interface
                .as_deref()
                .map_or(xdp::NicConfig::Default, xdp::NicConfig::Name),
            external_port: self.udp_port,
            maximum_packet_memory: self.xdp.maximum_memory,
            require_zero_copy: self.xdp.force_zerocopy,
            require_tx_checksum: self.xdp.force_tx_checksum_offload,
        })
        .context("failed to setup XDP")?;

        let io_loop = xdp::spawn(workers, config).context("failed to spawn XDP I/O loop")?;
        Ok(Box::new(move |srx: crate::ShutdownRx| {
            io_loop.shutdown(*srx.borrow() == crate::ShutdownKind::Normal);
        }))
    }
}

/// XDP (eXpress Data Path) options
#[derive(clap::Args, Clone, Debug)]
pub struct XdpOptions {
    /// The name of the network interface to bind the XDP socket(s) to.
    ///
    /// If not specified quilkin will attempt to determine the most appropriate
    /// network interface to use. Quilkin will exit with an error if the network
    /// interface does not exist, or a suitable default cannot be determined.
    #[clap(long = "service.udp.xdp.network-interface")]
    pub network_interface: Option<String>,
    /// Forces the use of XDP.
    ///
    /// If XDP is not available on the chosen NIC, Quilkin exits with an error.
    /// If false, io-uring will be used as the fallback implementation.
    #[clap(long = "service.udp.xdp")]
    pub force_xdp: bool,
    /// Forces the use of [`XDP_ZEROCOPY`](https://www.kernel.org/doc/html/latest/networking/af_xdp.html#xdp-copy-and-xdp-zerocopy-bind-flags)
    ///
    /// If zero copy is not available on the chosen NIC, Quilkin exits with an error
    #[clap(long = "service.udp.xdp.zerocopy")]
    pub force_zerocopy: bool,
    /// Forces the use of [TX checksum offload](https://docs.kernel.org/6.8/networking/xsk-tx-metadata.html)
    ///
    /// TX checksum offload is an optional feature allowing the data portion of
    /// a packet to have its internet checksum calculation offloaded to the NIC,
    /// as otherwise this is done in software
    #[clap(long = "service.udp.xdp.tco")]
    pub force_tx_checksum_offload: bool,
    /// The maximum amount of memory mapped for packet buffers, in bytes
    ///
    /// If not specified, this defaults to 4MiB (2k allocated packets of 2k each at a time)
    /// per NIC queue, ie 128MiB on a 32 queue NIC
    #[clap(long = "service.udp.xdp.memory-limit")]
    pub maximum_memory: Option<u64>,
}

#[allow(clippy::derivable_impls)]
impl Default for XdpOptions {
    fn default() -> Self {
        Self {
            network_interface: None,
            force_xdp: false,
            force_zerocopy: false,
            force_tx_checksum_offload: false,
            maximum_memory: None,
        }
    }
}
