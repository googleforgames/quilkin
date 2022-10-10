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

use std::collections::HashSet;

use super::{Config, Filter};
use crate::{
    cluster::ClusterMap,
    config::{Admin, ManagementServer, Proxy, ValidationError, Version},
};

/// Builder for a [`Config`]
#[derive(Debug)]
pub struct Builder {
    pub port: u16,
    pub admin: Option<Admin>,
    pub clusters: ClusterMap,
    pub filters: Vec<Filter>,
    pub management_servers: Vec<ManagementServer>,
    pub maxmind_db: Option<crate::maxmind_db::Source>,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            admin: Some(<_>::default()),
            port: <_>::default(),
            clusters: <_>::default(),
            filters: <_>::default(),
            management_servers: <_>::default(),
            maxmind_db: <_>::default(),
        }
    }
}

impl Builder {
    pub fn port(self, port: u16) -> Self {
        Builder { port, ..self }
    }

    pub fn filters(self, filters: impl Into<Vec<Filter>>) -> Self {
        Self {
            filters: filters.into(),
            ..self
        }
    }

    pub fn clusters(self, clusters: impl Into<ClusterMap>) -> Self {
        Self {
            clusters: clusters.into(),
            ..self
        }
    }

    pub fn endpoints(self, endpoints: impl Into<Vec<crate::endpoint::Endpoint>>) -> Self {
        Self {
            clusters: ClusterMap::new_with_default_cluster(
                endpoints
                    .into()
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>(),
            ),
            ..self
        }
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

    pub fn maxmind_db(self, mmdb: crate::maxmind_db::Source) -> Self {
        Self {
            maxmind_db: mmdb.into(),
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
        if !builder.clusters.contains_only_unique_endpoints() {
            return Err(ValidationError::NotUnique("clusters".into()));
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
            version: Version::V1Alpha1.into(),
            proxy: Proxy {
                id: "test".into(),
                port: builder.port,
            }
            .into(),
            admin: builder.admin.into(),
            clusters: builder.clusters.into(),
            filters: crate::filters::FilterChain::try_from(builder.filters)?.into(),
            management_servers: builder.management_servers.into(),
            metrics: <_>::default(),
            maxmind_db: builder.maxmind_db.into(),
        })
    }
}
