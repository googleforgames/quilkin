pub use std::net::UdpSocket as Socket;

pub const NAME: &str = "io_uring";

#[track_caller]
pub fn from_system_socket(socket: super::SystemSocket) -> Socket {
    Socket::from(socket.into_inner())
}

#[derive(Clone)]
pub struct Notifier(SystemNotifier);

impl Notifier {
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_self))]
    pub fn notify(&self) {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                self.0.write(1);
            }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub(crate) mod io_uring;
        pub use io_uring::{listen, is_available, queue};

        pub type Receiver = io_uring::EventFd;
        pub type SystemNotifier = io_uring::EventFdWriter;
    } else {
        pub type Receiver = ();
        pub type SystemNotifier = ();

        pub fn listen(_: super::Listener, _: crate::net::packet::PacketQueue) -> eyre::Result<()> { eyre::bail!("completion based io unavailable on platform") }
        pub fn is_available() -> bool { false }

        pub fn queue() -> std::io::Result<(crate::net::io::Notifier, crate::net::io::Receiver)> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "completion based io unavailable on platform"))
        }
    }
}
