use super::RunArgs;
use crate::config::{IcaoCode, Providers};
pub use crate::net::{endpoint::Locality, DualStackLocalSocket};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone, Debug, Default)]
pub struct Ready {
    pub provider_is_healthy: Arc<AtomicBool>,
    pub relay_is_healthy: Arc<AtomicBool>,
    /// If true, only care about the provider being healthy, not the relay
    pub is_manage: bool,
}

impl Ready {
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.provider_is_healthy.load(Ordering::SeqCst)
            && (self.is_manage || self.relay_is_healthy.load(Ordering::SeqCst))
    }
}

pub struct Agent {
    pub locality: Option<Locality>,
    pub qcmp_socket: socket2::Socket,
    pub icao_code: Option<IcaoCode>,
    pub relay_servers: Vec<tonic::transport::Endpoint>,
    pub provider: Option<Providers>,
    pub address_selector: Option<crate::config::AddressSelector>,
}

impl Agent {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        RunArgs {
            config,
            ready,
            mut shutdown_rx,
        }: RunArgs<Ready>,
    ) -> crate::Result<()> {
        {
            let crate::config::DatacenterConfig::Agent {
                icao_code,
                qcmp_port,
            } = &config.datacenter
            else {
                unreachable!("this should be an agent config");
            };

            qcmp_port.store(crate::net::socket_port(&self.qcmp_socket).into());
            icao_code.store(self.icao_code.unwrap_or_default().into());
        }

        let _mds_task = if !self.relay_servers.is_empty() {
            let _provider_task = match self.provider {
                Some(provider) => Some(provider.spawn(
                    config.clone(),
                    ready.provider_is_healthy.clone(),
                    self.locality,
                    self.address_selector,
                    true,
                )),
                None => return Err(eyre::eyre!("no configuration provider given")),
            };

            let task = crate::net::xds::client::MdsClient::connect(
                String::clone(&config.id.load()),
                self.relay_servers,
            );

            tokio::select! {
                result = task => {
                    let client = result?;

                    // The inner fields are unused.
                    #[allow(dead_code)]
                    enum XdsTask {
                        Delta(crate::net::xds::client::DeltaSubscription),
                        Aggregated(crate::net::xds::client::MdsStream),
                    }

                    // Attempt to connect to a delta stream if the relay has one
                    // available, otherwise fallback to the regular aggregated stream
                    Some(match client.delta_stream(config.clone(), ready.clone()).await {
                        Ok(ds) => XdsTask::Delta(ds),
                        Err(client) => {
                            XdsTask::Aggregated(client.mds_client_stream(config, ready))
                        }
                    })
                }
                _ = shutdown_rx.changed() => return Ok(()),
            }
        } else {
            tracing::info!("no relay servers given");
            None
        };

        crate::codec::qcmp::spawn(self.qcmp_socket, shutdown_rx.clone());
        shutdown_rx.changed().await.map_err(From::from)
    }
}
