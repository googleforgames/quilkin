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

use super::{Config, Filter};
use crate::{
    config::{Admin, Proxy, Source, Version},
    endpoint::Endpoint,
};

/// Builder for a [`Config`]
#[derive(Debug)]
pub struct Builder {
    pub port: u16,
    pub source: Source,
    pub admin: Admin,
}

impl Builder {
    /// Returns a [`Builder`] with empty values.
    pub fn empty() -> Self {
        Builder {
            port: 0,
            admin: Admin::default(),
            source: Source::Static {
                filters: vec![],
                endpoints: vec![],
            },
        }
    }

    pub fn with_port(self, port: u16) -> Self {
        Builder { port, ..self }
    }

    pub fn with_static(self, filters: Vec<Filter>, endpoints: Vec<Endpoint>) -> Self {
        let source = Source::Static { filters, endpoints };
        Builder { source, ..self }
    }

    pub fn with_admin(self, admin: Admin) -> Self {
        Self { admin, ..self }
    }

    pub fn build(self) -> Config {
        Config {
            version: Version::V1Alpha1,
            proxy: Proxy {
                id: "test".into(),
                port: self.port,
            },
            admin: self.admin,
            source: self.source,
        }
    }
}
