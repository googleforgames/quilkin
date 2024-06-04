use ::xds::generated::quilkin::config::v1alpha1 as proto;
use prost::Message;
use prost_types::Any;

pub const CLUSTER_TYPE: &str = "type.googleapis.com/quilkin.config.v1alpha1.Cluster";
pub const DATACENTER_TYPE: &str = "type.googleapis.com/quilkin.config.v1alpha1.Datacenter";
pub const FILTER_CHAIN_TYPE: &str = "type.googleapis.com/quilkin.config.v1alpha1.FilterChain";
const PREFIX: &str = "type.googleapis.com/quilkin.config.v1alpha1.";

pub enum Resource {
    Cluster(proto::Cluster),
    Datacenter(proto::Datacenter),
    FilterChain(proto::FilterChain),
}

impl Resource {
    #[inline]
    pub fn try_decode(any: Any) -> Result<Self, eyre::Error> {
        let Some(suffix) = any.type_url.strip_prefix(PREFIX) else {
            eyre::bail!("unknown resource type '{}'", any.type_url);
        };

        Ok(match suffix {
            "Cluster" => Self::Cluster(proto::Cluster::decode(&*any.value)?),
            "Datacenter" => Self::Datacenter(proto::Datacenter::decode(&*any.value)?),
            "FilterChain" => Self::FilterChain(proto::FilterChain::decode(&*any.value)?),
            _ => eyre::bail!("unknown resource type '{}'", any.type_url),
        })
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
        }
    }
}

#[derive(Copy, Clone)]
pub enum ResourceType {
    Cluster,
    Datacenter,
    FilterChain,
}

// impl ::xds::config::ResourceType for ResourceType {
//     fn url(&self) -> &'static str {
//         match self {
//             Self::Cluster => CLUSTER_TYPE,
//             Self::Datacenter => DATACENTER_TYPE,
//             Self::FilterChain => FILTER_CHAIN_TYPE,
//         }
//     }
// }

impl std::str::FromStr for ResourceType {
    type Err = eyre::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some(suffix) = s.strip_prefix(PREFIX) else {
            eyre::bail!("unknown resource type '{s}'");
        };

        Ok(match suffix {
            "Cluster" => Self::Cluster,
            "Datacenter" => Self::Datacenter,
            "FilterChain" => Self::FilterChain,
            _ => eyre::bail!("unknown resource type '{s}'"),
        })
    }
}

// #[derive(Default)]
// pub struct ClusterResource {
//     pub proto: proto::Cluster,
// }

// impl ResourceType for ClusterResource {
//     fn name(&self) -> String {
//         self.proto
//             .locality
//             .clone()
//             .map(|locality| crate::locality::Locality::from(locality).to_string())
//             .unwrap_or_default()
//     }

//     fn type_url(&self) -> &'static str {}

//     fn decode(&mut self, any: Any) -> Result<(), eyre::Error> {
//         self.proto = proto::Cluster::decode(&*any.value)?;
//         Ok(())
//     }

//     fn encode(&self) -> Result<Any, prost::EncodeError> {
//         Ok(Any {
//             type_url: self.type_url().into(),
//             value: {
//                 let mut buf = Vec::with_capacity(self.proto.encoded_len());
//                 self.proto.encode(&mut buf)?;
//                 buf
//             },
//         })
//     }
// }

// #[derive(Default)]
// pub struct DatacenterResource {
//     pub proto: proto::Datacenter,
// }

// impl ResourceType for DatacenterResource {
//     fn name(&self) -> String {
//         self.proto.icao_code.clone()
//     }

//     fn type_url(&self) -> &'static str {
//         "type.googleapis.com/quilkin.config.v1alpha1.Datacenter"
//     }

//     fn decode(&mut self, any: Any) -> Result<(), eyre::Error> {
//         self.proto = proto::Datacenter::decode(&*any.value)?;
//         Ok(())
//     }

//     fn encode(&self) -> Result<Any, prost::EncodeError> {
//         Ok(Any {
//             type_url: self.type_url().into(),
//             value: {
//                 let mut buf = Vec::with_capacity(self.proto.encoded_len());
//                 self.proto.encode(&mut buf)?;
//                 buf
//             },
//         })
//     }
// }

// #[derive(Default)]
// pub struct FilterChainResource {
//     pub proto: proto::FilterChain,
// }

// impl ResourceType for FilterChainResource {
//     fn name(&self) -> String {
//         String::new()
//     }

//     fn type_url(&self) -> &'static str {
//         "type.googleapis.com/quilkin.config.v1alpha1.FilterChain"
//     }

//     fn decode(&mut self, any: Any) -> Result<(), eyre::Error> {
//         self.proto = proto::FilterChain::decode(&*any.value)?;
//         Ok(())
//     }

//     fn encode(&self) -> Result<Any, prost::EncodeError> {
//         Ok(Any {
//             type_url: self.type_url().into(),
//             value: {
//                 let mut buf = Vec::with_capacity(self.proto.encoded_len());
//                 self.proto.encode(&mut buf)?;
//                 buf
//             },
//         })
//     }
// }
