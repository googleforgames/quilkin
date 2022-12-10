/// Watches Agones' game server CRDs for `Allocated` game server endpoints,
/// and for a `ConfigMap` that specifies the filter configuration.
#[derive(Debug, Clone, clap::Args)]
pub struct Kubernetes {
    /// The namespace under which the configmap is stored.
    #[clap(short, long, default_value = "default")]
    pub config_namespace: String,
    /// The namespace under which the game servers run.
    #[clap(short, long, default_value = "default")]
    pub gameservers_namespace: String,
}
