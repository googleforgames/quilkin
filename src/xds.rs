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

use ::quilkin_xds::generated::quilkin::config::v1alpha1 as proto;
use prost::Message;
use prost_types::Any;

pub const CLUSTER_TYPE: &str = "type.googleapis.com/quilkin.config.v1alpha1.Cluster";
pub const DATACENTER_TYPE: &str = "type.googleapis.com/quilkin.config.v1alpha1.Datacenter";
pub const FILTER_CHAIN_TYPE: &str = "type.googleapis.com/quilkin.config.v1alpha1.FilterChain";
pub const LISTENER_TYPE: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
const PREFIX: &str = "type.googleapis.com/quilkin.config.v1alpha1.";

pub enum Resource {
    Cluster(proto::Cluster),
    Datacenter(proto::Datacenter),
    FilterChain(proto::FilterChain),
    Listener(proto::FilterChain),
}

impl Resource {
    #[inline]
    pub fn try_decode(any: Any) -> Result<Self, eyre::Error> {
        let Some(suffix) = any.type_url.strip_prefix(PREFIX) else {
            if any.type_url == LISTENER_TYPE {
                return Self::decode_listener(&any.value);
            } else {
                eyre::bail!("unknown resource type '{}'", any.type_url);
            }
        };

        Ok(match suffix {
            "Cluster" => Self::Cluster(proto::Cluster::decode(&*any.value)?),
            "Datacenter" => Self::Datacenter(proto::Datacenter::decode(&*any.value)?),
            "FilterChain" => Self::FilterChain(proto::FilterChain::decode(&*any.value)?),
            _ => eyre::bail!("unknown resource type '{}'", any.type_url),
        })
    }

    #[inline]
    fn decode_listener(buf: &[u8]) -> eyre::Result<Self> {
        use eyre::Context as _;

        let mut listener =
            quilkin_xds::generated::envoy::config::listener::v3::Listener::decode(buf)?;
        eyre::ensure!(
            !listener.filter_chains.is_empty(),
            "{LISTENER_TYPE} resource had no filter chains"
        );
        eyre::ensure!(
            listener.filter_chains.len() == 1,
            "{LISTENER_TYPE} resource had more than one filter chain"
        );
        let filter_chain = listener.filter_chains.swap_remove(0);

        let filters = filter_chain
            .filters
            .into_iter()
            .map(|filter| {
                use quilkin_xds::generated::envoy::config::listener::v3::filter::ConfigType;

                let config = if let Some(config_type) = filter.config_type {
                    let config = match config_type {
                        ConfigType::TypedConfig(any) => any,
                        ConfigType::ConfigDiscovery(_) => {
                            eyre::bail!("ConfigDiscovery is not supported")
                        }
                    };

                    Some(String::from_utf8(config.value).context("filter config was non-utf8")?)
                } else {
                    None
                };

                tracing::info!("LISTENER CONFIG: '{config:?}'");

                Ok(proto::Filter {
                    name: filter.name,
                    label: None,
                    config,
                })
            })
            .collect::<eyre::Result<Vec<_>>>()?;

        Ok(Self::Listener(proto::FilterChain { filters }))
    }

    #[inline]
    pub fn try_encode(&self) -> Result<Any, prost::EncodeError> {
        let (value, type_url) = match self {
            Self::Cluster(c) => {
                let mut value = Vec::with_capacity(c.encoded_len());
                c.encode(&mut value)?;
                (value, CLUSTER_TYPE)
            }
            Self::Datacenter(d) => {
                let mut value = Vec::with_capacity(d.encoded_len());
                d.encode(&mut value)?;
                (value, DATACENTER_TYPE)
            }
            Self::FilterChain(f) => {
                let mut value = Vec::with_capacity(f.encoded_len());
                f.encode(&mut value)?;
                (value, FILTER_CHAIN_TYPE)
            }
            Self::Listener(f) => {
                let l = quilkin_xds::generated::envoy::config::listener::v3::Listener {
                    filter_chains: vec![quilkin_xds::generated::envoy::config::listener::v3::FilterChain {
                        filters: f.filters.iter().map(|f| {
                            quilkin_xds::generated::envoy::config::listener::v3::Filter {
                                name: f.name.clone(),
                                config_type: if let Some(cfg) = &f.config {
                                    let cfg = prost_types::Any {
                                        type_url: f.name.clone(),
                                        value: cfg.clone().into(),
                                    };
                                    Some(quilkin_xds::generated::envoy::config::listener::v3::filter::ConfigType::TypedConfig(cfg))
                                } else {
                                    None
                                },
                            }
                        }).collect(),
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                let mut value = Vec::with_capacity(l.encoded_len());
                l.encode(&mut value)?;
                (value, LISTENER_TYPE)
            }
        };

        Ok(Any {
            type_url: type_url.into(),
            value,
        })
    }

    #[inline]
    pub fn type_url(&self) -> &'static str {
        match self {
            Self::Cluster(_) => CLUSTER_TYPE,
            Self::Datacenter(_) => DATACENTER_TYPE,
            Self::FilterChain(_) => FILTER_CHAIN_TYPE,
            Self::Listener(_) => LISTENER_TYPE,
        }
    }
}

#[derive(Copy, Clone)]
pub enum ResourceType {
    Cluster,
    Datacenter,
    FilterChain,
    Listener,
}

impl std::str::FromStr for ResourceType {
    type Err = eyre::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(suffix) = s.strip_prefix(PREFIX) else {
            if s == LISTENER_TYPE {
                return Ok(Self::Listener);
            } else {
                eyre::bail!("unknown resource type '{s}'");
            }
        };

        Ok(match suffix {
            "Cluster" => Self::Cluster,
            "Datacenter" => Self::Datacenter,
            "FilterChain" => Self::FilterChain,
            _ => eyre::bail!("unknown resource type '{s}'"),
        })
    }
}
