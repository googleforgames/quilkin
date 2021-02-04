/*
 * Copyright 2020 Google LLC All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::config::{parse_endpoint_metadata_from_yaml, EndPoint};
use serde_json::value::Value;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

pub(crate) mod cluster_manager;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub tokens: HashSet<Vec<u8>>,
    pub metadata: Option<Value>,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct Locality {
    pub region: String,
    pub zone: String,
    pub sub_zone: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalityEndpoints {
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cluster {
    pub localities: ClusterLocalities,
}

pub type ClusterLocalities = HashMap<Option<Locality>, LocalityEndpoints>;

impl Endpoint {
    pub fn new(address: SocketAddr, tokens: HashSet<Vec<u8>>, metadata: Option<Value>) -> Endpoint {
        Endpoint {
            address,
            tokens,
            metadata,
        }
    }

    pub fn from_address(address: SocketAddr) -> Endpoint {
        Endpoint::new(address, Default::default(), None)
    }

    /// Converts an endpoint config into an internal endpoint representation.
    pub fn from_config(config: &EndPoint) -> Result<Endpoint, String> {
        let (metadata, tokens) = if let Some(metadata) = config.metadata.clone() {
            let (metadata, tokens) = parse_endpoint_metadata_from_yaml(metadata)?;
            (Some(metadata), tokens)
        } else {
            (None, Default::default())
        };

        Ok(Endpoint::new(config.address, tokens, metadata))
    }
}
