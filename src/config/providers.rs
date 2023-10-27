use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
pub mod k8s;

const RETRIES: u32 = 25;
const BACKOFF_STEP: std::time::Duration = std::time::Duration::from_millis(250);
pub const MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(60 * 5);

/// The available xDS source providers.
#[derive(Clone, Debug, clap::Subcommand)]
pub enum Providers {
    /// Watches Agones' game server CRDs for `Allocated` game server endpoints,
    /// and for a `ConfigMap` that specifies the filter configuration.
    Agones {
        /// The namespace under which the configmap is stored.
        #[clap(
            short,
            long,
            env = "QUILKIN_AGONES_CONFIG_NAMESPACE",
            default_value = "default"
        )]
        config_namespace: String,
        /// The namespace under which the game servers run.
        #[clap(
            short,
            long,
            env = "QUILKIN_AGONES_GAMESERVERS_NAMESPACE",
            default_value = "default"
        )]
        gameservers_namespace: String,
        /// The maximum delay in seconds to watch for changes of agones.
        #[clap(short, long, env = "QUILKIN_AGONES_MAX_DELAY", default_value = "300")]
        max_delay_in_seconds: u64,
    },

    /// Watches for changes to the file located at `path`.
    File {
        /// The path to the source config.
        #[clap(env = "QUILKIN_FS_PATH")]
        path: std::path::PathBuf,
    },
}

impl Providers {
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn spawn(
        &self,
        config: std::sync::Arc<crate::Config>,
        health_check: Arc<AtomicBool>,
        locality: Option<crate::net::endpoint::Locality>,
    ) -> tokio::task::JoinHandle<crate::Result<()>> {
        match &self {
            Self::Agones {
                gameservers_namespace,
                config_namespace,
                max_delay_in_seconds,
            } => tokio::spawn(Self::task(
                health_check.clone(),
                {
                    let gameservers_namespace = gameservers_namespace.clone();
                    let config_namespace = config_namespace.clone();
                    let health_check = health_check.clone();
                    move || {
                        crate::config::watch::agones(
                            gameservers_namespace.clone(),
                            config_namespace.clone(),
                            health_check.clone(),
                            locality.clone(),
                            config.clone(),
                        )
                    }
                },
                std::time::Duration::from_secs(*max_delay_in_seconds),
            )),
            Self::File { path } => tokio::spawn(Self::task(
                health_check.clone(),
                {
                    let path = path.clone();
                    let health_check = health_check.clone();
                    move || {
                        crate::config::watch::fs(
                            config.clone(),
                            health_check.clone(),
                            path.clone(),
                            locality.clone(),
                        )
                    }
                },
                MAX_DELAY,
            )),
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn task<F>(
        health_check: Arc<AtomicBool>,
        task: impl FnMut() -> F,
        retry_max_delay: std::time::Duration,
    ) -> crate::Result<()>
    where
        F: std::future::Future<Output = crate::Result<()>>,
    {
        tryhard::retry_fn(task)
            .retries(RETRIES)
            .exponential_backoff(BACKOFF_STEP)
            .max_delay(retry_max_delay)
            .on_retry(|attempt, _, error: &eyre::Error| {
                health_check.store(false, Ordering::SeqCst);
                let error = error.to_string();
                async move {
                    tracing::warn!(%attempt, %error, "provider task error, retrying");
                }
            })
            .await
    }
}
