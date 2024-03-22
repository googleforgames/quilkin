pub mod admin;
pub mod agent;
pub mod manage;
pub mod proxy;
pub mod relay;

/// Args common across all components
pub struct RunArgs<T> {
    /// Config
    pub config: std::sync::Arc<crate::Config>,
    /// The ready check and idle duration
    pub ready: T,
    /// Channel used to indicate graceful shutdown requests
    pub shutdown_rx: crate::ShutdownRx,
}
