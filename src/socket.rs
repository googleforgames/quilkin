pub(crate) mod metrics;
mod session;

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, Mutex};

use crate::{
    cluster::SharedCluster,
    endpoint::{Endpoint, EndpointAddress, Endpoints, UpstreamEndpoints},
    filters::{prelude::*, SharedFilterChain},
    proxy::{ValidatedConfig, ValidatedSource},
};

use self::{metrics::Metrics, session::Session};

/// A Quilkin socket.
///
/// [`Socket`] represents the main the entry for network communication with
/// quilkin. This socket behaves similarly (though not exactly) like a UDP
/// socket.
///
/// A quilkin socket is different from a regular socket in that it always
/// assumes that's its a bridge between two other services (named downstream and
/// upstream).
///
/// # Cloning
/// [`Socket`]'s `Clone` implementation is a shallow clone, so cloning it should
/// be considered a cheap operation, and that work is being distributed amongst
/// all active socket instances.
#[derive(Clone)]
pub struct Socket {
    inner: Arc<Inner>,
}

struct Inner {
    cluster: SharedCluster,
    downstream: ArcSwap<tokio::net::UdpSocket>,
    filters: SharedFilterChain,
    metrics: Metrics,
    session: Session,
    xds_background_task: ArcSwap<Option<tokio::task::JoinHandle<()>>>,
    xds_client_channel: ArcSwap<Mutex<Option<mpsc::Receiver<crate::Result<()>>>>>,
}

impl Socket {
    #[tracing::instrument(skip_all)]
    pub async fn bind<A: tokio::net::ToSocketAddrs>(
        addrs: A,
        filters: &[crate::config::Filter],
    ) -> crate::Result<Self> {
        let downstream = ArcSwap::new(Arc::new(tokio::net::UdpSocket::bind(addrs).await?));
        let filters = SharedFilterChain::try_from(filters)?;
        let cluster = SharedCluster::empty()?;

        Ok(Self {
            inner: Arc::new(Inner {
                cluster,
                downstream,
                filters,
                metrics: Metrics::new()?,
                session: <_>::default(),
                xds_background_task: <_>::default(),
                xds_client_channel: <_>::default(),
            }),
        })
    }

    /// Binds a Quilkin socket without any filters.
    #[tracing::instrument(skip_all)]
    pub async fn bind_empty<A: tokio::net::ToSocketAddrs>(addrs: A) -> crate::Result<Self> {
        Self::bind(addrs, &[]).await
    }

    /// Binds a Quilkin socket from a validated configuration.
    #[tracing::instrument(skip_all)]
    pub async fn bind_from_config(
        config: &ValidatedConfig,
        shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> crate::Result<Self> {
        let this = Self::bind_empty((std::net::Ipv4Addr::UNSPECIFIED, config.proxy.port)).await?;

        match &config.source {
            ValidatedSource::Static {
                filter_chain: filters,
                endpoints,
            } => {
                this.update_filters(&filters)?;
                this.set_static_upstream(endpoints.to_vec());
            }
            ValidatedSource::Dynamic { management_servers } => {
                this.connect_to_xds(
                    config.proxy.id.clone(),
                    management_servers.clone(),
                    shutdown_rx,
                )
                .await?;
            }
        }

        Ok(this)
    }

    /// Binds Quilkin to use a xDS management service for determining properties
    /// like filter chain and upstream clusters.
    pub async fn bind_to_xds<A, S>(
        addrs: A,
        id: S,
        management_servers: Vec<crate::config::ManagementServer>,
        shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> crate::Result<Self>
    where
        A: tokio::net::ToSocketAddrs,
        S: Into<String>,
    {
        let this = Self::bind_empty(addrs).await?;
        this.connect_to_xds(id.into(), management_servers, shutdown_rx)
            .await?;
        Ok(this)
    }

    /// Returns the local socket address of the downstream ingress socket.
    pub fn local_addr(&self) -> std::io::Result<EndpointAddress> {
        self.inner
            .downstream
            .load()
            .local_addr()
            .map(EndpointAddress::from)
    }

    /// Returns the currently connected cluster.
    pub(crate) fn cluster(&self) -> SharedCluster {
        self.inner.cluster.clone()
    }

    /// Returns a handle to the current filter chain.
    pub fn filters(&self) -> SharedFilterChain {
        self.inner.filters.clone()
    }

    /// Returns a handle to the current filter chain.
    pub fn update_filters(&self, filters: &[crate::config::Filter]) -> crate::Result<()> {
        self.inner.filters.store(filters)?;
        Ok(())
    }

    /// Set the socket to use a static set of endpoints.
    #[tracing::instrument(skip_all)]
    pub fn set_static_upstream(&self, endpoints: Vec<Endpoint>) {
        self.set_cluster(crate::cluster::ClusterMap::new_static(endpoints));
    }

    /// Connect an existing socket to an xDS management for managing properties.
    /// Note: that this will replace any currently connected cluster and xDS
    /// management server.
    #[tracing::instrument(skip_all)]
    pub async fn connect_to_xds<S>(
        &self,
        id: S,
        management_servers: Vec<crate::config::ManagementServer>,
        shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) -> crate::Result<()>
    where
        S: Into<String>,
    {
        self.abort_xds_task().await;
        let (client_channel_tx, client_channel_rx) = tokio::sync::mpsc::channel(1);
        let client = crate::xds::AdsClient::new()?;
        let id = id.into();
        let this = self.clone();
        let task = tokio::spawn(async move {
            let client = client.run(id, management_servers, this, shutdown_rx);

            let result = client.await;
            result.unwrap();

            client_channel_tx.send(Ok(())).await.unwrap();
        });

        self.inner
            .xds_client_channel
            .store(Arc::new(Mutex::new(Some(client_channel_rx))));
        self.inner.xds_background_task.store(Arc::new(Some(task)));

        Ok(())
    }

    /// Receives a `(packet, upstream, downstream)` message from all the
    /// currently active upstream endpoints.
    #[tracing::instrument(skip_all)]
    pub async fn receive_upstream(
        &self,
    ) -> crate::Result<impl Iterator<Item = (Vec<u8>, EndpointAddress, EndpointAddress)>> {
        let iter = self
            .inner
            .session
            .instances()
            .await
            .into_iter()
            .map(|session| {
                tokio::spawn(async move {
                    Ok((
                        session.recv().await?,
                        session.upstream().clone(),
                        session.downstream().clone(),
                    ))
                })
            })
            .into_iter();

        let mut results = Vec::new();

        for result in iter {
            let result: crate::Result<(Vec<u8>, EndpointAddress, EndpointAddress)> = result.await?;
            results.push(result?);
        }

        Ok(results.into_iter())
    }

    /// Sends a packet `upstream` from `downstream`, after processing it through
    /// the filter chain, and provided it wasn't dropped in processing.
    #[tracing::instrument(skip_all)]
    pub async fn send_upstream(
        &self,
        buf: &[u8],
        upstream: impl Into<EndpointAddress>,
        downstream: impl Into<EndpointAddress>,
    ) -> crate::Result<()> {
        let session = self
            .inner
            .session
            .instance(upstream.into(), downstream.into())
            .await?;
        session.send(buf).await?;
        Ok(())
    }

    /// Attempts to receive a packet from the bound socket, returning the last
    /// valid response from the filter. This method waits until a valid packet
    /// has passed through the filters.
    #[tracing::instrument(skip_all)]
    pub async fn receive_downstream(
        &self,
        to: Vec<Endpoint>,
    ) -> crate::Result<(ReadResponse, EndpointAddress)> {
        loop {
            if let Some(response) = self.try_receive_downstream(&to).await? {
                return Ok(response);
            }
        }
    }

    /// Attempts to receive a packet from the bound socket, returning the last
    /// response from the filter, or `None` if the packet was dropped while
    /// processing.
    #[tracing::instrument(skip_all)]
    async fn try_receive_downstream(
        &self,
        to: &[Endpoint],
    ) -> crate::Result<Option<(ReadResponse, EndpointAddress)>> {
        let mut buf = vec![0; u16::MAX as usize];
        let (length, addr) = self.inner.downstream.load().recv_from(&mut buf).await?;
        let downstream = EndpointAddress::from(addr);

        if to.is_empty() {
            self.inner.metrics.packets_dropped_no_endpoints.inc();
            return Ok(None);
        };

        let result = self.inner.filters.read(ReadContext::new(
            UpstreamEndpoints::from(Endpoints::new(to.into())),
            downstream.clone(),
            Vec::from(&buf[..length]),
        ));

        if let Some(ctx) = result {
            for endpoint in ctx.endpoints.iter() {
                self.inner
                    .session
                    .instance(endpoint.address.clone(), downstream.clone())
                    .await?;
            }
            Ok(Some((ctx, downstream)))
        } else {
            Ok(None)
        }
    }

    /// Sends a packet to `downstream` from `upstream`, after processing `buf`
    /// through the `write` side of the filter chain, and hasn't been dropped
    /// by the filter chain.
    #[tracing::instrument(skip_all)]
    pub async fn send_downstream<A, B>(
        &self,
        buf: Vec<u8>,
        upstream: A,
        downstream: B,
    ) -> crate::Result<()>
    where
        A: tokio::net::ToSocketAddrs,
        B: tokio::net::ToSocketAddrs,
    {
        let source = EndpointAddress::lookup_host(upstream).await?;
        let dest = EndpointAddress::lookup_host(downstream).await?;

        let endpoint = Endpoint::new(source.clone().into());

        let result = self.inner.filters.write(WriteContext::new(
            &endpoint,
            source.into(),
            dest.clone().into(),
            buf,
        ));

        if let Some(response) = result {
            self.inner
                .downstream
                .load()
                .send_to(&response.contents, dest.to_socket_addr()?)
                .await?;
        }

        Ok(())
    }

    #[tracing::instrument(skip_all)]
    pub async fn process_worker(self) -> crate::Result<()> {
        loop {
            let xds_task_failed = async {
                let mutex = self.inner.xds_client_channel.load();
                let mut lock = mutex.lock().await;
                if let Some(ref mut task) = *lock {
                    task.recv().await
                } else {
                    drop(lock);
                    std::future::pending().await
                }
            };

            let receive_downstream = async {
                match self.inner.cluster.endpoints() {
                    Some(endpoints) => {
                        self.receive_downstream(endpoints.iter().cloned().collect())
                            .await
                    }
                    None => std::future::pending().await,
                }
            };

            tokio::select! {
                upstreams = self.receive_upstream() => {
                    for (buf, upstream, downstream) in upstreams? {
                        self.send_downstream(buf, upstream.to_socket_addr()?, downstream.to_socket_addr()?).await?;
                    }
                }
                result = receive_downstream => {
                    let (response, addr) = result?;

                    for endpoint in response.endpoints.iter() {
                        self.send_upstream(&response.contents, endpoint.address.to_socket_addr()?, addr.to_socket_addr()?).await?;
                    }
                }
                result = xds_task_failed => {
                    match result {
                        Some(Ok(())) | None => return Ok(()),
                        Some(Err(error)) => return Err(error)
                    }
                }
            }
        }
    }

    #[tracing::instrument(skip_all)]
    pub(crate) fn set_cluster(&self, cluster: crate::cluster::ClusterMap) {
        self.inner.cluster.store(cluster);
    }

    async fn abort_xds_task(&self) {
        if let Some(task) = &**self.inner.xds_background_task.load() {
            task.abort();
            self.inner.xds_client_channel.load().lock().await.take();
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        if let Some(task) = &**self.inner.xds_background_task.load() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNSPECIFIED: (std::net::Ipv4Addr, u16) = (std::net::Ipv4Addr::UNSPECIFIED, 0);

    #[tokio::test]
    async fn simple_round_trip() {
        const PACKET: &[u8] = b"Hello World!";
        let client = tokio::net::UdpSocket::bind(UNSPECIFIED).await.unwrap();
        let server = tokio::net::UdpSocket::bind(UNSPECIFIED).await.unwrap();
        let quilkin = Socket::bind(UNSPECIFIED, &[]).await.unwrap();

        let quilkin_addr = EndpointAddress::from(quilkin.local_addr().unwrap());
        let server_addr = EndpointAddress::from(server.local_addr().unwrap());
        client
            .send_to(PACKET, quilkin_addr.clone().to_socket_addr().unwrap())
            .await
            .unwrap();
        let (response, addr) = quilkin
            .receive_downstream(vec![EndpointAddress::from(server_addr.clone()).into()])
            .await
            .unwrap();
        assert_eq!(PACKET, &response.contents);
        quilkin
            .send_upstream(&response.contents, server_addr, addr)
            .await
            .unwrap();

        let (contents, addr) = {
            let mut buf = vec![0; u16::MAX as usize];
            let (length, addr) = server.recv_from(&mut buf).await.unwrap();
            (Vec::from(&buf[..length]), addr)
        };

        assert_eq!(PACKET, contents);
        server.send_to(&contents, addr).await.unwrap();
        let (contents, upstream, downstream) =
            quilkin.receive_upstream().await.unwrap().next().unwrap();
        assert_eq!(PACKET, &contents);
        quilkin
            .send_downstream(
                contents,
                upstream.to_socket_addr().unwrap(),
                downstream.to_socket_addr().unwrap(),
            )
            .await
            .unwrap();

        let contents = {
            let mut buf = vec![0; u16::MAX as usize];
            let (length, _) = client.recv_from(&mut buf).await.unwrap();
            Vec::from(&buf[..length])
        };

        assert_eq!(PACKET, contents);
    }
}
