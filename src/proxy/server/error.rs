use crate::proxy::sessions::error::Error as SessionError;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Initialize(String),
    Session(SessionError),
    Bind(tokio::io::Error),
}

#[derive(Debug)]
pub(super) struct RecvFromError(pub tokio::io::Error);

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Initialize(reason) => write!(f, "failed to startup properly: {}", reason),
            Error::Session(inner) => write!(f, "session error: {}", inner),
            Error::Bind(inner) => write!(f, "failed to bind to port: {}", inner),
        }
    }
}

impl Display for RecvFromError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "recv_from error: {}", self.0)
    }
}
