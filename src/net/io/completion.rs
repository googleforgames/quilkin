cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod io_uring;
        pub use io_uring::{listen, is_available};
    } else {
        pub fn listen(_: super::Listener, _: crate::net::PacketQueue) -> eyre::Result<()> { eyre::bail!("completion based io unavailable on platform") }
        pub fn is_available() -> bool { false }
    }
}
