use std::{fmt, hash::Hash};

#[derive(Debug)]
pub enum PipelineError {
    NoUpstreamEndpoints,
    Filter(crate::filters::FilterError),
    Session(super::sessions::SessionError),
    Io(std::io::Error),
    ChannelClosed,
    ChannelFull,
    /// This occurs if a receive task has accumulated so many errors that the
    /// error details had to be dropped in order to reduce memory pressure
    AccumulatorOverflow,
}

impl PipelineError {
    pub fn discriminant(&self) -> &'static str {
        match self {
            Self::NoUpstreamEndpoints => "no upstream endpoints",
            Self::Filter(fe) => fe.discriminant(),
            Self::Session(_) => "session",
            Self::Io(_) => "io",
            Self::ChannelClosed => "channel closed",
            Self::ChannelFull => "channel full",
            Self::AccumulatorOverflow => "error accumulator overflow",
        }
    }
}

impl std::error::Error for PipelineError {}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoUpstreamEndpoints => f.write_str("No upstream endpoints available"),
            Self::Filter(fe) => write!(f, "filter {fe}"),
            Self::Session(session) => write!(f, "session error: {session}"),
            Self::Io(io) => write!(f, "OS level error: {io}"),
            Self::ChannelClosed => f.write_str("channel closed"),
            Self::ChannelFull => f.write_str("channel full"),
            Self::AccumulatorOverflow => f.write_str("error accumulator overflow"),
        }
    }
}

impl From<std::io::Error> for PipelineError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<super::sessions::SessionError> for PipelineError {
    fn from(value: super::sessions::SessionError) -> Self {
        Self::Session(value)
    }
}

impl PartialEq for PipelineError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NoUpstreamEndpoints, Self::NoUpstreamEndpoints) => true,
            (Self::Filter(fa), Self::Filter(fb)) => fa.eq(fb),
            (Self::Session(sa), Self::Session(sb)) => sa.eq(sb),
            (Self::Io(ia), Self::Io(ib)) => ia.kind().eq(&ib.kind()),
            (Self::ChannelClosed, Self::ChannelClosed) => true,
            (Self::ChannelFull, Self::ChannelFull) => true,
            (Self::AccumulatorOverflow, Self::AccumulatorOverflow) => true,
            _ => false,
        }
    }
}

impl Eq for PipelineError {}

impl Hash for PipelineError {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let disc = std::mem::discriminant(self);
        Hash::hash(&disc, state);

        match self {
            Self::Filter(fe) => Hash::hash(&fe, state),
            Self::Session(se) => Hash::hash(&se, state),
            Self::Io(io) => Hash::hash(&io.kind(), state),
            Self::NoUpstreamEndpoints
            | Self::ChannelClosed
            | Self::ChannelFull
            | Self::AccumulatorOverflow => {}
        }
    }
}

pub struct SeahashBuilder;

impl std::hash::BuildHasher for SeahashBuilder {
    type Hasher = seahash::SeaHasher;

    fn build_hasher(&self) -> Self::Hasher {
        seahash::SeaHasher::new()
    }
}

pub type ErrorMap = std::collections::HashMap<PipelineError, u64, SeahashBuilder>;

pub type ErrorSender = tokio::sync::mpsc::Sender<ErrorMap>;
//pub type ErrorReceiver = tokio::sync::mpsc::Receiver<ErrorMap>;

/// The soft cap of errors after which we try to send them to the collation task
const CAP_ERRORS: usize = 10 * 1024;
/// The maximum errors that can be accumulated before being dropped and lost
const MAX_ERRORS: usize = 100 * 1024;
const MAX_ELAPSED: std::time::Duration = std::time::Duration::from_secs(5);

use std::time::Instant;

/// Accumulates errors on downstream receiver tasks before sending them for collation
///
/// If many errors occur and
pub struct ErrorAccumulator {
    map: ErrorMap,
    tx: ErrorSender,
    oldest: Instant,
}

impl ErrorAccumulator {
    pub fn new(tx: ErrorSender) -> Self {
        Self {
            map: ErrorMap::with_hasher(SeahashBuilder),
            tx,
            oldest: Instant::now(),
        }
    }

    pub fn maybe_send(&mut self) -> bool {
        if self.map.is_empty() || self.oldest.elapsed() < MAX_ELAPSED {
            return false;
        }

        self.do_send()
    }

    fn do_send(&mut self) -> bool {
        let Ok(permit) = self.tx.try_reserve() else {
            return false;
        };

        let map = std::mem::replace(&mut self.map, ErrorMap::with_hasher(SeahashBuilder));
        permit.send(map);
        true
    }

    pub fn push_error(&mut self, error: PipelineError) {
        if self.map.is_empty() {
            self.oldest = Instant::now();
        }

        *self.map.entry(error).or_default() += 1;

        if self.map.len() >= CAP_ERRORS {
            if self.do_send() {
                return;
            }

            // If we failed to send and we've reach our max capacity, reset and
            // note the fact that we did so
            if self.map.len() >= MAX_ERRORS {
                self.map.clear();
                self.map.insert(PipelineError::AccumulatorOverflow, 1);
                self.oldest = Instant::now();
            }
        }

        if self.oldest.elapsed() >= MAX_ELAPSED {
            self.do_send();
        }
    }
}
