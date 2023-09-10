/*
 * Copyright 2022 Google LLC
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

use prost::Message;

use crate::xds::config::listener::v3::Listener;

pub type ResourceMap<V> = enum_map::EnumMap<ResourceType, V>;

macro_rules! type_urls {
     ($($base_url:literal : {$($const_name:ident = $type_url:literal),+ $(,)?})+) => {
         $(
             $(
                 const $const_name : &str = concat!($base_url, "/", $type_url);
             )+
         )+
     }
 }

type_urls! {
    "type.googleapis.com": {
        CLUSTER_TYPE = "quilkin.config.v1alpha1.Cluster",
        LISTENER_TYPE = "envoy.config.listener.v3.Listener",
    }
}

#[derive(Clone, Debug)]
pub enum Resource {
    Cluster(Box<crate::cluster::proto::Cluster>),
    Listener(Box<Listener>),
}

impl Resource {
    pub fn name(&self) -> String {
        match self {
            Self::Cluster(cluster) => cluster
                .locality
                .clone()
                .map(|locality| crate::endpoint::Locality::from(locality).to_string())
                .unwrap_or_default(),
            Self::Listener(listener) => listener.name.to_string(),
        }
    }

    pub fn resource_type(&self) -> ResourceType {
        match self {
            Self::Cluster(_) => ResourceType::Cluster,
            Self::Listener(_) => ResourceType::Listener,
        }
    }

    pub fn type_url(&self) -> &str {
        self.resource_type().type_url()
    }
}

impl TryFrom<prost_types::Any> for Resource {
    type Error = eyre::Error;

    fn try_from(any: prost_types::Any) -> Result<Self, Self::Error> {
        Ok(match &*any.type_url {
            CLUSTER_TYPE => Resource::Cluster(<_>::decode(&*any.value)?),
            LISTENER_TYPE => Resource::Listener(<_>::decode(&*any.value)?),
            url => return Err(UnknownResourceType(url.into()).into()),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, enum_map::Enum)]
pub enum ResourceType {
    Cluster,
    Listener,
}

impl ResourceType {
    pub const VARIANTS: &'static [Self] = &[Self::Cluster, Self::Listener];

    /// Returns the corresponding type URL for the response type.
    pub const fn type_url(&self) -> &'static str {
        match self {
            Self::Cluster => CLUSTER_TYPE,
            Self::Listener => LISTENER_TYPE,
        }
    }

    pub fn encode_to_any<M: prost::Message>(
        self,
        message: &M,
    ) -> Result<prost_types::Any, prost::EncodeError> {
        Ok(prost_types::Any {
            type_url: self.type_url().into(),
            value: crate::prost::encode(message)?,
        })
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.type_url())
    }
}

impl TryFrom<&'_ str> for ResourceType {
    type Error = UnknownResourceType;

    fn try_from(url: &str) -> Result<Self, UnknownResourceType> {
        Ok(match url {
            CLUSTER_TYPE => Self::Cluster,
            LISTENER_TYPE => Self::Listener,
            unknown => return Err(UnknownResourceType(unknown.to_owned())),
        })
    }
}

impl std::str::FromStr for ResourceType {
    type Err = UnknownResourceType;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        Self::try_from(string)
    }
}

impl TryFrom<String> for ResourceType {
    type Error = UnknownResourceType;

    fn try_from(url: String) -> Result<Self, UnknownResourceType> {
        Self::try_from(&*url)
    }
}

impl TryFrom<&'_ String> for ResourceType {
    type Error = UnknownResourceType;

    fn try_from(url: &String) -> Result<Self, UnknownResourceType> {
        Self::try_from(&**url)
    }
}

/// Error indicating an unknown resource type was found.
#[derive(Debug, thiserror::Error)]
#[error("Unknown resource type: {0}")]
pub struct UnknownResourceType(String);

impl From<UnknownResourceType> for tonic::Status {
    fn from(error: UnknownResourceType) -> Self {
        tonic::Status::invalid_argument(error.to_string())
    }
}
