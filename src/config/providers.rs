pub mod k8s;

const RETRIES: u32 = 25;
const BACKOFF_STEP: std::time::Duration = std::time::Duration::from_millis(250);

/// The available xDS source providers.
#[derive(Clone, Debug, clap::Subcommand)]
pub enum Providers {
    /// Watches Agones' game server CRDs for `Allocated` game server endpoints,
    /// and for a `ConfigMap` that specifies the filter configuration.
    Agones {
        /// The namespace under which the configmap is stored.
        #[clap(short, long, default_value = "default")]
        config_namespace: String,
        /// The namespace under which the game servers run.
        #[clap(short, long, default_value = "default")]
        gameservers_namespace: String,
    },

    /// Watches for changes to the file located at `path`.
    File {
        /// The path to the source config.
        path: std::path::PathBuf,
    },
}

impl Providers {
    #[tracing::instrument(level = "trace", skip_all)]
    pub fn spawn(
        &self,
        config: std::sync::Arc<crate::Config>,
        locality: Option<crate::endpoint::Locality>,
    ) -> tokio::task::JoinHandle<crate::Result<()>> {
        match &self {
            Self::Agones {
                gameservers_namespace,
                config_namespace,
            } => tokio::spawn(Self::task({
                let gameservers_namespace = gameservers_namespace.clone();
                let config_namespace = config_namespace.clone();
                move || {
                    crate::config::watch::agones(
                        gameservers_namespace.clone(),
                        config_namespace.clone(),
                        locality.clone(),
                        config.clone(),
                    )
                }
            })),
            Self::File { path } => tokio::spawn(Self::task({
                let path = path.clone();
                move || crate::config::watch::fs(config.clone(), path.clone(), locality.clone())
            })),
        }
    }

    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn task<F>(task: impl FnMut() -> F) -> crate::Result<()>
    where
        F: std::future::Future<Output = crate::Result<()>>,
    {
        tryhard::retry_fn(task)
            .retries(RETRIES)
            .exponential_backoff(BACKOFF_STEP)
            .on_retry(|attempt, _, error: &eyre::Error| {
                let error = error.to_string();
                async move {
                    tracing::warn!(%attempt, %error, "provider task error, retrying");
                }
            })
            .await
    }
}
