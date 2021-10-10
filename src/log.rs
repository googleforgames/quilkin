use slog::{o, Drain};
use slog_term::{FullFormat, PlainSyncDecorator};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;

/// Logger is an optionally rate-limited logger.
pub struct Logger {
    pub inner: slog::Logger,
    tokens: Arc<AtomicU64>,
    max_messages_per_sec: usize,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

pub type SharedLogger = Arc<Logger>;

impl Drop for Logger {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            // Ignore any error when sending the shutdown signal since
            // it means the receiver is no longer on the other end anyway.
            shutdown_tx.send(()).ok();
        }
    }
}

impl Logger {
    /// Returns a child logger. Note that the root logger still must continue to be in scope
    /// otherwise the returned logger could get permanently rate limited.
    pub fn child<T>(&self, values: slog::OwnedKV<T>) -> SharedLogger
    where
        T: slog::SendSyncRefUnwindSafeKV + 'static,
    {
        Arc::new(Logger {
            inner: self.inner.new(values),
            tokens: self.tokens.clone(),
            max_messages_per_sec: self.max_messages_per_sec,
            // No shutdown since only one token bucket exists and refill is done
            // by the root logger.
            shutdown_tx: None,
        })
    }

    /// Returns a root logger that is rate limited.
    pub fn with_rate_limit(inner: slog::Logger, max_messages_per_sec: usize) -> SharedLogger {
        Self::new(inner, Some(max_messages_per_sec))
    }

    /// Returns a root logger that is optionally rate limited.
    pub fn new(inner: slog::Logger, max_messages_per_sec: Option<usize>) -> SharedLogger {
        // If we have a rate limit, then spawn a background task to refill tokens.
        let (max_messages_per_sec, tokens, shutdown_tx) =
            if let Some(max_messages_per_sec) = max_messages_per_sec {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
                let tokens = Arc::new(AtomicU64::new(0));
                let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

                let reset_tokens = tokens.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = interval.tick() => {
                                reset_tokens.store(0, Ordering::Relaxed);
                            },
                            _ = &mut shutdown_rx => {
                                break;
                            }
                        }
                    }
                });

                (max_messages_per_sec, tokens, Some(shutdown_tx))
            } else {
                // If not running with rate limit, use max values so we never run out of tokens.
                (usize::MAX, Arc::new(AtomicU64::new(0)), None)
            };

        Arc::new(Logger {
            inner,
            tokens,
            max_messages_per_sec,
            shutdown_tx,
        })
    }

    pub fn acquire_token(&self) -> Option<()> {
        match self.tokens.fetch_add(1, Ordering::Relaxed) {
            v if v == self.max_messages_per_sec as u64 => {
                // We've now crossed the rate limit threshold, notify only once.
                slog::warn!(self.inner, "Log messages are being rate limited"; "limit" => format!("{}/s", self.max_messages_per_sec));
                None
            }
            v if v > self.max_messages_per_sec as u64 => None,
            _ => Some(()),
        }
    }
}

#[macro_export]
macro_rules! error (
    ($l:expr, #$tag:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::error!($l.inner, $tag, $($args)+)
        }
    };
    ($l:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::error!($l.inner, $($args)+)
        }
    };
);

#[macro_export]
macro_rules! warn (
    ($l:expr, #$tag:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::warn!($l.inner, $tag, $($args)+)
        }
    };
    ($l:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::warn!($l.inner, $($args)+)
        }
    };
);

#[macro_export]
macro_rules! info (
    ($l:expr, #$tag:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::info!($l.inner, $tag, $($args)+)
        }
    };
    ($l:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::info!($l.inner, $($args)+)
        }
    };
);

#[macro_export]
macro_rules! debug (
    ($l:expr, #$tag:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::debug!($l.inner, $tag, $($args)+)
        }
    };
    ($l:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::debug!($l.inner, $($args)+)
        }
    };
);

#[macro_export]
macro_rules! trace (
    ($l:expr, #$tag:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::trace!($l.inner, $tag, $($args)+)
        }
    };
    ($l:expr, $($args:tt)+) => {
        if let Some(()) = $l.acquire_token() {
            slog::trace!($l.inner, $($args)+)
        }
    };
);

/// Returns a rate limited logger that logs via JSON format.
pub fn create_default_rate_limited_logger() -> SharedLogger {
    let drain = slog_json::Json::new(std::io::stdout())
        .set_pretty(false)
        .add_default_keys()
        .build()
        .fuse();
    let async_logger = slog_async::Async::new(drain).build().fuse();

    Logger::with_rate_limit(slog::Logger::root(async_logger, o!()), 50)
}

// Returns a standard out, non rate-limited, non structured terminal logger
// suitable for using in tests since it's more human readable.
pub fn test_logger() -> SharedLogger {
    let plain = PlainSyncDecorator::new(std::io::stdout());
    let drain = FullFormat::new(plain).build().fuse();
    Logger::new(slog::Logger::root(drain, o!()), None)
}

#[cfg(test)]
mod tests {
    use crate::test_utils::eventually;
    use slog::{o, Drain};
    use std::io::Write;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::time;

    #[derive(Clone)]
    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut inner = self.0.lock().unwrap();
            inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            let mut inner = self.0.lock().unwrap();
            inner.flush()
        }
    }
    impl Sink {
        fn collect(&mut self) -> String {
            self.flush().unwrap();
            let mut inner = self.0.lock().unwrap();
            String::from_utf8(std::mem::take(&mut *inner)).unwrap()
        }
    }

    fn rate_limited_logger(max: usize) -> (super::SharedLogger, Sink) {
        let sink = Sink(Arc::new(Mutex::new(Vec::new())));
        (
            super::Logger::with_rate_limit(
                slog::Logger::root(
                    slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(sink.clone()))
                        .build()
                        .fuse(),
                    o!(),
                ),
                max,
            ),
            sink,
        )
    }
    #[tokio::test]
    async fn rate_limit_max() {
        // Test that we do not log messages after hitting the rate limit window.

        let max = 2;
        let (log, mut sink) = rate_limited_logger(max);
        for i in 0..max * 2 {
            warn!(log, "line"; "count" => i);
        }

        let output = sink.collect();
        assert_eq!((max + 1) as usize, output.lines().count());

        for i in 0..max {
            assert!(output.contains(format!("WARN line, count: {}\n", i).as_str()));
        }
        assert!(output.contains("WARN Log messages are being rate limited, limit: 2/s"));
    }

    #[tokio::test]
    async fn rate_limit_refill_tokens() {
        // Test that we reset the token counter after the rate limit window has elapsed.

        time::pause();

        let max = 2;
        let (log, mut sink) = rate_limited_logger(max);
        for i in 0..max * 2 {
            warn!(log, "line"; "count" => i);
        }

        let output = sink.collect();
        assert_eq!((max + 1) as usize, output.lines().count());

        for i in 0..max {
            assert!(output.contains(format!("WARN line, count: {}\n", i).as_str()));
        }
        assert!(output.contains("WARN Log messages are being rate limited, limit: 2/s"));

        time::advance(std::time::Duration::from_secs(2)).await;

        // Wait for a token refill.
        eventually(
            || (log.tokens.load(Ordering::SeqCst) == 0).then(|| ()),
            Duration::from_millis(10),
            Duration::from_millis(500),
        )
        .await
        .unwrap();

        // Try logging again, we should be able to log new lines now.
        for i in 0..max * 2 {
            warn!(log, "line 2"; "count" => i);
        }

        let output = sink.collect();
        assert_eq!((max + 1) as usize, output.lines().count());

        for i in 0..max {
            assert!(output.contains(format!("WARN line 2, count: {}\n", i).as_str()));
        }
        assert!(output.contains("WARN Log messages are being rate limited, limit: 2/s"));
    }

    #[tokio::test]
    async fn logging_levels() {
        let max = 10;
        let (log, mut sink) = rate_limited_logger(max);
        error!(log, "error");
        warn!(log, "warn");
        info!(log, "info");
        debug!(log, "debug");
        trace!(log, "trace");

        let output = sink.collect();
        assert_eq!(4, output.lines().count());

        assert!(output.contains("WARN warn\n"));
        assert!(output.contains("ERRO error\n"));
        assert!(output.contains("INFO info\n"));
        assert!(output.contains("DEBG debug\n"));
    }

    #[tokio::test]
    async fn child() {
        let max = 10;
        let (log, mut sink) = rate_limited_logger(max);

        let child = log.child(slog::o!("foo" => "bar"));

        warn!(child, "child log 1");

        let output = sink.collect();
        assert_eq!(1, output.lines().count());

        assert!(output.contains("WARN child log 1"));
    }
}
