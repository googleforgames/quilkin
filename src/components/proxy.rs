pub mod packet_router;
mod sessions;

use super::RunArgs;
use crate::{
    net::{maxmind_db::IpNetEntry, xds::ResourceType},
    pool::PoolBuffer,
};
pub use sessions::SessionPool;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

#[derive(thiserror::Error, Debug, strum_macros::EnumDiscriminants)]
#[strum_discriminants(derive(strum_macros::Display))]
pub enum PipelineError {
    #[error("No upstream endpoints available")]
    NoUpstreamEndpoints,
    #[error("filter {0}")]
    Filter(#[from] crate::filters::FilterError),
    #[error("session error: {0}")]
    Session(#[from] eyre::Error),
    #[error("OS level error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Channel closed")]
    ChannelClosed,
    #[error("Under pressure")]
    ChannelFull,
}

#[derive(Clone, Debug, Default)]
pub struct Ready {
    pub idle_request_interval: std::time::Duration,
    // RwLock as this check is conditional on the proxy using xDS.
    pub xds_is_healthy: Arc<parking_lot::RwLock<Option<Arc<AtomicBool>>>>,
}

impl Ready {
    #[inline]
    pub fn is_ready(&self) -> Option<bool> {
        self.xds_is_healthy
            .read()
            .as_ref()
            .map(|health| health.load(Ordering::SeqCst))
    }
}

pub struct Proxy {
    pub num_workers: std::num::NonZeroUsize,
    pub mmdb: Option<crate::net::maxmind_db::Source>,
    pub management_servers: Vec<tonic::transport::Endpoint>,
    pub to: Vec<SocketAddr>,
    pub socket: socket2::Socket,
    pub qcmp: socket2::Socket,
    pub phoenix: crate::net::TcpListener,
}

impl Default for Proxy {
    fn default() -> Self {
        let qcmp = crate::net::raw_socket_with_reuse(0).unwrap();
        let phoenix = crate::net::TcpListener::bind(Some(crate::net::socket_port(&qcmp))).unwrap();

        Self {
            num_workers: std::num::NonZeroUsize::new(1).unwrap(),
            mmdb: None,
            management_servers: Vec::new(),
            to: Vec::new(),
            socket: crate::net::raw_socket_with_reuse(0).unwrap(),
            qcmp,
            phoenix,
        }
    }
}

impl Proxy {
    pub async fn run(
        self,
        RunArgs {
            config,
            ready,
            mut shutdown_rx,
        }: RunArgs<Ready>,
        initialized: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> crate::Result<()> {
        let _mmdb_task = self.mmdb.map(|source| {
            tokio::spawn(async move {
                while let Err(error) =
                    tryhard::retry_fn(|| crate::MaxmindDb::update(source.clone()))
                        .retries(10)
                        .exponential_backoff(crate::config::BACKOFF_INITIAL_DELAY)
                        .await
                {
                    tracing::warn!(%error, "error updating maxmind database");
                }
            })
        });

        if !self.to.is_empty() {
            config.clusters.modify(|clusters| {
                clusters.insert(
                    None,
                    self.to
                        .iter()
                        .cloned()
                        .map(crate::net::endpoint::Endpoint::from)
                        .collect(),
                );
            });
        }

        if !config.clusters.read().has_endpoints() && self.management_servers.is_empty() {
            return Err(eyre::eyre!(
                 "`quilkin proxy` requires at least one `to` address or `management_server` endpoint."
             ));
        }

        let id = config.id.load();
        let num_workers = self.num_workers.get();

        let (upstream_sender, upstream_receiver) =
            async_channel::bounded::<(PoolBuffer, Option<IpNetEntry>, SocketAddr)>(250);
        let buffer_pool = Arc::new(crate::pool::BufferPool::new(num_workers, 64 * 1024));
        let sessions = SessionPool::new(
            config.clone(),
            upstream_sender,
            buffer_pool.clone(),
            shutdown_rx.clone(),
        );

        if !self.management_servers.is_empty() {
            {
                let mut lock = ready.xds_is_healthy.write();
                let check: Arc<AtomicBool> = <_>::default();
                *lock = Some(check.clone());
            }

            std::thread::Builder::new()
                .name("proxy-subscription".into())
                .spawn({
                    let config = config.clone();
                    let mut shutdown_rx = shutdown_rx.clone();
                    let management_servers = self.management_servers.clone();

                    move || {
                        let runtime = tokio::runtime::Builder::new_multi_thread()
                            .enable_all()
                            .thread_name_fn(|| {
                                static ATOMIC_ID: std::sync::atomic::AtomicUsize =
                                    std::sync::atomic::AtomicUsize::new(0);
                                let id =
                                    ATOMIC_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                format!("proxy-subscription-{id}")
                            })
                            .build()
                            .unwrap();

                        runtime.block_on(async move {
                            let client = crate::net::xds::AdsClient::connect(
                                String::clone(&id),
                                management_servers,
                            )
                            .await?;

                            let mut delta_sub = None;
                            let mut state_sub = None;
                            let xds_is_healthy =
                                ready.xds_is_healthy.read().as_ref().unwrap().clone();

                            match client
                                .delta_subscribe(
                                    config.clone(),
                                    xds_is_healthy.clone(),
                                    [
                                        (ResourceType::Cluster, Vec::new()),
                                        (ResourceType::Listener, Vec::new()),
                                        (ResourceType::Datacenter, Vec::new()),
                                    ],
                                )
                                .await
                            {
                                Ok(ds) => delta_sub = Some(ds),
                                Err(client) => {
                                    let mut stream =
                                        client.xds_client_stream(config, xds_is_healthy);

                                    tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
                                    stream
                                        .aggregated_subscribe(ResourceType::Cluster, &[])
                                        .await?;
                                    tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
                                    stream
                                        .aggregated_subscribe(ResourceType::Listener, &[])
                                        .await?;
                                    tokio::time::sleep(std::time::Duration::from_nanos(1)).await;
                                    stream
                                        .aggregated_subscribe(ResourceType::Datacenter, &[])
                                        .await?;

                                    state_sub = Some(stream);
                                }
                            }

                            let _ = shutdown_rx.changed().await;
                            drop(delta_sub);
                            drop(state_sub);
                            Ok::<_, eyre::Error>(())
                        })
                    }
                })
                .expect("failed to spawn proxy-subscription thread");
        }

        let worker_notifications = packet_router::spawn_receivers(
            config.clone(),
            self.socket,
            num_workers,
            &sessions,
            upstream_receiver,
            buffer_pool,
        )
        .await?;

        crate::codec::qcmp::spawn(self.qcmp, shutdown_rx.clone());
        crate::net::phoenix::spawn(
            self.phoenix,
            config.clone(),
            shutdown_rx.clone(),
            crate::net::phoenix::Phoenix::new(crate::codec::qcmp::QcmpMeasurement::new()?),
        )?;

        for notification in worker_notifications {
            notification.notified().await;
        }

        tracing::info!("Quilkin is ready");
        if let Some(initialized) = initialized {
            let _ = initialized.send(());
        }

        shutdown_rx
            .changed()
            .await
            .map_err(|error| eyre::eyre!(error))?;

        if *shutdown_rx.borrow() == crate::ShutdownKind::Normal {
            tracing::info!(sessions=%sessions.sessions().len(), "waiting for active sessions to expire");

            let interval = std::time::Duration::from_millis(100);

            while sessions.sessions().is_not_empty() {
                tokio::time::sleep(interval).await;
                tracing::debug!(sessions=%sessions.sessions().len(), "sessions still active");
            }
            tracing::info!("all sessions expired");
        }

        Ok(())
    }
}
