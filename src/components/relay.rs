use super::RunArgs;
use crate::{config::Providers, net::TcpListener};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Debug)]
pub struct Ready {
    pub idle_request_interval: std::time::Duration,
    pub provider_is_healthy: Arc<AtomicBool>,
}

impl Default for Ready {
    fn default() -> Self {
        Self {
            idle_request_interval: crate::components::admin::IDLE_REQUEST_INTERVAL,
            provider_is_healthy: Default::default(),
        }
    }
}

impl Ready {
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.provider_is_healthy.load(Ordering::SeqCst)
    }
}

pub struct Relay {
    pub xds_listener: TcpListener,
    pub mds_listener: TcpListener,
    pub provider: Option<Providers>,
}

impl Relay {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        RunArgs {
            config,
            ready,
            mut shutdown_rx,
        }: RunArgs<Ready>,
    ) -> crate::Result<()> {
        use crate::net::xds::server::ControlPlane;

        let xds_server = ControlPlane::from_arc(config.clone(), ready.idle_request_interval)
            .management_server(self.xds_listener)?;
        let mds_server = tokio::spawn(
            ControlPlane::from_arc(config.clone(), ready.idle_request_interval)
                .relay_server(self.mds_listener)?,
        );

        let _provider_task = self.provider.map(|provider| {
            let config = config.clone();
            let provider_is_healthy = ready.provider_is_healthy.clone();

            match provider {
                Providers::Agones {
                    config_namespace, ..
                } => {
                    let config_namespace = config_namespace.unwrap_or_else(|| "default".into());
                    let fut = Providers::task(provider_is_healthy.clone(), move || {
                        let config = config.clone();
                        let config_namespace = config_namespace.clone();
                        let provider_is_healthy = provider_is_healthy.clone();
                        async move {
                            let client = tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                kube::Client::try_default(),
                            )
                            .await??;

                            let configmap_reflector =
                                crate::config::providers::k8s::update_filters_from_configmap(
                                    client.clone(),
                                    &config_namespace,
                                    config.clone(),
                                );

                            use tokio_stream::StreamExt;
                            tokio::pin!(configmap_reflector);

                            loop {
                                match configmap_reflector.next().await {
                                    Some(Ok(_)) => {
                                        provider_is_healthy.store(true, Ordering::SeqCst);
                                    }
                                    Some(Err(error)) => {
                                        provider_is_healthy.store(false, Ordering::SeqCst);
                                        return Err(error);
                                    }
                                    None => {
                                        provider_is_healthy.store(false, Ordering::SeqCst);
                                        break;
                                    }
                                }
                            }

                            tracing::info!("configmap stream ending");
                            Ok(())
                        }
                    });

                    tokio::spawn(fut)
                }
                Providers::File { path } => {
                    tokio::spawn(Providers::task(provider_is_healthy.clone(), move || {
                        let config = config.clone();
                        let path = path.clone();
                        let provider_is_healthy = provider_is_healthy.clone();
                        async move {
                            crate::config::watch::fs(config, provider_is_healthy, path, None).await
                        }
                    }))
                }
            }
        });

        tokio::select! {
            result = xds_server => {
                result
            }
            result = mds_server => {
                result?
            }
            result = shutdown_rx.changed() => result.map_err(From::from),
        }
    }
}
