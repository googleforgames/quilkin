/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

use std::{collections::HashSet, sync::Arc};

use arc_swap::ArcSwap;

use super::{Config, Filter};
use crate::{
    config::{Admin, ManagementServer, Proxy, ValidationError, Version},
    endpoint::Endpoint,
};

/// Builder for a [`Config`]
#[derive(Debug)]
pub struct Builder {
    pub port: u16,
    pub admin: Option<Admin>,
    pub endpoints: Vec<Endpoint>,
    pub filters: Vec<Filter>,
    pub management_servers: Vec<ManagementServer>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            admin: Some(<_>::default()),
            port: <_>::default(),
            endpoints: <_>::default(),
            filters: <_>::default(),
            management_servers: <_>::default(),
        }
    }
}

impl Builder {
    pub fn port(self, port: u16) -> Self {
        Builder { port, ..self }
    }

    pub fn filters(self, filters: Vec<Filter>) -> Self {
        Self { filters, ..self }
    }

    pub fn endpoints(self, endpoints: Vec<Endpoint>) -> Self {
        Self { endpoints, ..self }
    }

    pub fn management_servers(self, management_servers: impl IntoIterator<Item = String>) -> Self {
        let management_servers = management_servers
            .into_iter()
            .map(|address| ManagementServer { address })
            .collect();
        Self {
            management_servers,
            ..self
        }
    }

    pub fn admin(self, admin: impl Into<Option<Admin>>) -> Self {
        Self {
            admin: admin.into(),
            ..self
        }
    }

    pub fn build(self) -> crate::Result<Config> {
        self.try_into().map_err(<_>::from)
    }
}

impl TryFrom<Builder> for Config {
    type Error = ValidationError;

    fn try_from(builder: Builder) -> Result<Self, Self::Error> {
        if builder
            .endpoints
            .iter()
            .map(|ep| ep.address.clone())
            .collect::<HashSet<_>>()
            .len()
            != builder.endpoints.len()
        {
            return Err(ValidationError::NotUnique(
                "static.endpoints.address".to_string(),
            ));
        }

        if builder
            .management_servers
            .iter()
            .map(|server| &server.address)
            .collect::<HashSet<_>>()
            .len()
            != builder.management_servers.len()
        {
            return Err(ValidationError::NotUnique(
                "dynamic.management_servers.address".to_string(),
            ));
        }

        Ok(Self {
            version: Version::V1Alpha1,
            proxy: Proxy {
                id: "test".into(),
                port: builder.port,
            },
            admin: builder.admin,
            endpoints: Arc::from(ArcSwap::new(Arc::from(builder.endpoints))),
            filters: Arc::from(ArcSwap::new(Arc::from(builder.filters))),
            management_servers: Arc::from(ArcSwap::new(Arc::from(builder.management_servers))),
        })
    }
}
