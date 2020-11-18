use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    BindUdpSocket(tokio::io::Error),
    SendToDst(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::BindUdpSocket(inner) => {
                write!(f, "failed to bind to UDP socket on address: {}", inner)
            }
            Error::SendToDst(inner) => write!(
                f,
                "failed to send a packet to the destination address: {}",
                inner
            ),
        }
    }
}

impl std::error::Error for Error {}
