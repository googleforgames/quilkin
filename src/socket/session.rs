mod metrics;

use std::sync::Arc;

use self::metrics::Metrics;
use crate::endpoint::EndpointAddress;

pub struct Session {
    sessions: Arc<
        tokio::sync::Mutex<cached::TimedCache<(EndpointAddress, EndpointAddress), SessionInstance>>,
    >,
}

impl Session {
    pub async fn instance(
        &self,
        upstream: EndpointAddress,
        downstream: EndpointAddress,
    ) -> crate::Result<SessionInstance> {
        use cached::Cached;
        let key = &(upstream, downstream);
        let mut lock = self.sessions.lock().await;

        if let Some(session) = lock.cache_get(key).cloned() {
            Ok(session)
        } else {
            let (upstream, downstream) = key;
            let new_session = SessionInstance::new(upstream.clone(), downstream.clone()).await?;
            lock.cache_set((upstream.clone(), downstream.clone()), new_session.clone());
            Ok(new_session)
        }
    }

    pub async fn instances(&self) -> Vec<SessionInstance> {
        self.flush().await;
        self.sessions
            .lock()
            .await
            .get_store()
            .values()
            .map(|(_, instance)| instance.clone())
            .collect()
    }

    async fn flush(&self) {
        self.sessions.lock().await.flush();
    }
}

impl Default for Session {
    fn default() -> Self {
        Self {
            sessions: Arc::new(tokio::sync::Mutex::new(
                cached::TimedCache::with_lifespan_and_refresh(60, true),
            )),
        }
    }
}

#[derive(Clone)]
pub struct SessionInstance {
    inner: Arc<Inner>,
}

struct Inner {
    metrics: Metrics,
    downstream: EndpointAddress,
    socket: Arc<tokio::net::UdpSocket>,
    upstream: EndpointAddress,
    created_at: std::time::Instant,
}

impl SessionInstance {
    pub async fn new(
        upstream: EndpointAddress,
        downstream: EndpointAddress,
    ) -> crate::Result<Self> {
        let socket =
            Arc::new(tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await?);
        let metrics = Metrics::new()?;
        let created_at = std::time::Instant::now();

        metrics.active_sessions.inc();
        metrics.sessions_total.inc();

        Ok(Self {
            inner: Arc::new(Inner {
                created_at,
                downstream,
                metrics,
                socket,
                upstream,
            }),
        })
    }

    /// Sends a packet upstream.
    pub async fn send(&self, vec: &[u8]) -> crate::Result<()> {
        self.inner
            .socket
            .send_to(vec, self.upstream().to_socket_addr()?)
            .await
            .map_err(|error| {
                self.inner.metrics.tx_errors_total.inc();
                error
            })?;
        self.inner.metrics.tx_bytes_total.inc_by(vec.len() as u64);
        self.inner.metrics.tx_packets_total.inc();
        Ok(())
    }

    /// Receives a single packet from the upstream socket in the session.
    pub async fn recv(&self) -> crate::Result<Vec<u8>> {
        let mut vec = vec![0; u16::MAX as usize];
        let (length, _) = self
            .inner
            .socket
            .recv_from(&mut vec)
            .await
            .map_err(|error| {
                self.inner.metrics.rx_errors_total.inc();
                error
            })?;
        self.inner.metrics.rx_bytes_total.inc_by(length as u64);
        self.inner.metrics.rx_packets_total.inc();
        Ok(vec[..length].to_owned())
    }

    /// Returns the upstream address of this session.
    pub fn upstream(&self) -> &EndpointAddress {
        &self.inner.upstream
    }

    /// Returns the downstream address of this session.
    pub fn downstream(&self) -> &EndpointAddress {
        &self.inner.downstream
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.metrics.active_sessions.dec();
        self.metrics
            .duration_secs
            .observe(self.created_at.elapsed().as_secs() as f64);
    }
}
