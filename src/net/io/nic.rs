cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod xdp;
        pub use xdp::{listen, is_available};
    } else {
        pub fn listen(_config: &std::sync::Arc<crate::config::Config>, _udp_port: u16, _qcmp_port: u16, _xdp: crate::cli::proxy::XdpOptions) -> crate::Result<crate::cli::Finalizer> { eyre::bail!("NIC I/O backend unavailable for platform") }
        pub fn is_available() -> bool { false }
    }
}
