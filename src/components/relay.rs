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

use super::RunArgs;
use crate::config::Providers;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug)]
pub struct Ready {
    pub idle_request_interval: std::time::Duration,
    pub provider_is_healthy: Arc<AtomicBool>,
}

impl Default for Ready {
    fn default() -> Self {
        Self {
            idle_request_interval: crate::components::admin::IDLE_REQUEST_INTERVAL,
            provider_is_healthy: Default::default(),
        }
    }
}

impl Ready {
    #[inline]
    pub fn is_ready(&self) -> bool {
        self.provider_is_healthy.load(Ordering::SeqCst)
    }
}

pub struct Relay {
    pub xds_port: u16,
    pub mds_port: u16,
    pub locality: Option<crate::net::endpoint::Locality>,
    pub provider: Option<Providers>,
}

impl Relay {
    #[tracing::instrument(skip_all)]
    pub async fn run(
        self,
        RunArgs {
            config,
            ready,
            mut shutdown_rx,
        }: RunArgs<Ready>,
    ) -> crate::Result<()> {
        let _provider_task = match self.provider {
            Some(Providers::Agones {
                config_namespace, ..
            }) => crate::config::providersv2::Providers::default()
                .k8s()
                .k8s_namespace(config_namespace.unwrap_or_default())
                .spawn_providers(&config, ready.provider_is_healthy.clone(), self.locality),

            Some(Providers::File { path }) => crate::config::providersv2::Providers::default()
                .fs()
                .fs_path(path)
                .spawn_providers(&config, ready.provider_is_healthy.clone(), self.locality),

            None => tokio::spawn(std::future::pending()),
        };

        crate::cli::Service::default()
            .xds()
            .xds_port(self.xds_port)
            .mds()
            .mds_port(self.mds_port)
            .spawn_services(&config, &shutdown_rx)?;

        shutdown_rx.changed().await.map_err(From::from)
    }
}
