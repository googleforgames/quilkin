pub use super::agent::Ready;
use super::RunArgs;
pub use crate::{
    config::Providers,
    net::{endpoint::Locality, DualStackLocalSocket},
};

pub struct Manage {
    pub locality: Option<Locality>,
    pub relay_servers: Vec<tonic::transport::Endpoint>,
    pub provider: Providers,
    pub listener: crate::net::TcpListener,
}

impl Manage {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        RunArgs {
            config,
            ready,
            mut shutdown_rx,
        }: RunArgs<Ready>,
    ) -> crate::Result<()> {
        if let Some(locality) = &self.locality {
            config
                .clusters
                .modify(|map| map.update_unlocated_endpoints(locality.clone()));
        }

        let provider_task = self.provider.spawn(
            config.clone(),
            ready.provider_is_healthy.clone(),
            self.locality,
        );

        let idle_request_interval = ready.idle_request_interval;

        let _relay_stream = if !self.relay_servers.is_empty() {
            tracing::info!("connecting to relay server");
            let client = crate::net::xds::client::MdsClient::connect(
                String::clone(&config.id.load()),
                self.relay_servers,
            )
            .await?;

            enum XdsTask {
                Delta(crate::net::xds::client::DeltaSubscription),
                Aggregated(crate::net::xds::client::MdsStream),
            }

            // Attempt to connect to a delta stream if the relay has one
            // available, otherwise fallback to the regular aggregated stream
            Some(
                match client.delta_stream(config.clone(), ready.clone()).await {
                    Ok(ds) => XdsTask::Delta(ds),
                    Err(client) => {
                        XdsTask::Aggregated(client.mds_client_stream(config.clone(), ready))
                    }
                },
            )
        } else {
            None
        };

        use futures::TryFutureExt as _;
        let server_task = tokio::spawn(crate::net::xds::server::spawn(
            self.listener,
            config,
            idle_request_interval,
        )?)
        .map_err(From::from)
        .and_then(std::future::ready);

        tokio::select! {
            result = server_task => result,
            result = provider_task => result?,
            result = shutdown_rx.changed() => result.map_err(From::from),
        }
    }
}
