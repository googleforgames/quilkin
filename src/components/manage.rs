/*
 * Copyright 2024 Google LLC All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

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
            None,
            false,
        );

        let _relay_stream = if !self.relay_servers.is_empty() {
            tracing::info!("connecting to relay server");
            let client = crate::net::xds::client::MdsClient::connect(
                String::clone(&config.id.load()),
                self.relay_servers,
            )
            .await?;

            // Attempt to connect to a delta stream if the relay has one
            // available, otherwise fallback to the regular aggregated stream
            Some(
                client
                    .delta_stream(config.clone(), ready.relay_is_healthy.clone())
                    .await
                    .map_err(|_| eyre::eyre!("failed to acquire delta stream"))?,
            )
        } else {
            None
        };

        use futures::TryFutureExt as _;
        let server_task = tokio::spawn(
            crate::net::xds::server::ControlPlane::from_arc(
                config,
                crate::components::admin::IDLE_REQUEST_INTERVAL,
            )
            .management_server(self.listener)?,
        )
        .map_err(From::from)
        .and_then(std::future::ready);

        tokio::select! {
            result = server_task => result,
            result = provider_task => result?,
            result = shutdown_rx.changed() => result.map_err(From::from),
        }
    }
}
