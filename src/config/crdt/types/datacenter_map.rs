use crate::{
    config::{
        IcaoCode,
        crdt::{
            collections::{self, CmRDT, ContentEqual, map::Op as MapOp},
            //state::StateSerializer,
            node_ip::{NodeAddress, NodeIp, UnknownIp},
        },
    },
    generated::envoy::service::discovery::v3::Resource as XdsResource,
};
use std::{collections::HashSet, sync::Arc};

pub type DatacenterMapCollection =
    collections::Map<IcaoCode, collections::Orswot<NodeAddress, NodeIp>, NodeIp>;
pub type DatacenterMapOp = MapOp<IcaoCode, collections::Orswot<NodeAddress, NodeIp>, NodeIp>;

impl typemap_rev::TypeMapKey for XdsDatacenterMap {
    type Value = Arc<XdsDatacenterMap>;
}

impl typemap_rev::TypeMapKey for PhoenixDatacenterMap {
    type Value = Arc<PhoenixDatacenterMap>;
}

impl crate::config::DynamicConfig {
    #[inline]
    pub fn xds_datacenters(&self) -> Option<&Arc<XdsDatacenterMap>> {
        self.typemap.get::<XdsDatacenterMap>()
    }

    #[inline]
    pub fn phoenix_datacenters(&self) -> Option<&Arc<PhoenixDatacenterMap>> {
        self.typemap.get::<PhoenixDatacenterMap>()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Datacenter {
    pub qcmp_port: u16,
    pub icao_code: IcaoCode,
}

#[derive(Debug)]
pub struct XdsDatacenterMap {
    dm: parking_lot::Mutex<DatacenterMapCollection>,
    local_ip: NodeIp,
    tx: tokio::sync::broadcast::Sender<()>,
}

impl XdsDatacenterMap {
    pub fn new() -> Result<Self, UnknownIp> {
        let local_ip = NodeIp::local_ip()?;
        Ok(Self {
            local_ip,
            dm: Default::default(),
            tx: tokio::sync::broadcast::channel(100).0,
        })
    }

    pub fn serialize_snapshot(
        &self,
        resources: &mut Vec<XdsResource>,
        removed: &mut HashSet<String>,
        cs: &quilkin_xds::config::ClientState,
    ) {
        let dm = self.dm.lock();
        for (icao, endpoints) in &dm.entries {
            let icaos = icao.to_string();
            for (endpoint, clock) in &endpoints.val.entries {
                let resource = {
                    let res =
                        crate::xds::Resource::Datacenter(crate::net::cluster::proto::Datacenter {
                            qcmp_port: endpoint.port as u32,
                            icao_code: icaos.clone(),
                            host: endpoint.ip.to_string(),
                        });

                    match res.try_encode() {
                        Ok(res) => Some(res),
                        Err(error) => {
                            tracing::error!(%icao, %error, "failed to encode DatacenterMap xDS resource");
                            continue;
                        }
                    }
                };

                match serde_json::to_string(clock) {
                    Ok(version) => {
                        let name = format!("{icao}-{endpoint}");
                        if cs.version_matches(&name, &version) {
                            continue;
                        }

                        resources.push(XdsResource {
                            name,
                            resource,
                            version,
                            aliases: Vec::new(),
                            ttl: None,
                            cache_control: None,
                        });
                    }
                    Err(error) => {
                        tracing::error!(%icao, %error, "failed to serialize DatacenterMap xDS resource version");
                    }
                }
            }
        }

        {
            for key in cs.versions.keys() {
                let Some((icao, endpoint)) = parse_crdt_key(key) else {
                    continue;
                };
                if let Some(endpoints) = dm.entries.get(&icao) {
                    if endpoints.val.entries.contains_key(&endpoint) {
                        continue;
                    }
                }

                removed.insert(key.clone());
            }
        }
    }

    #[inline]
    pub fn upsert_datacenters(&self, resources: Vec<XdsResource>, ip: std::net::IpAddr) {
        let ip = ip.into();
        let rmed = self.remove_ip(ip);

        let mut upserted = false;
        for res in resources {
            let Some(resource) = res.resource else {
                tracing::error!(
                    res.name,
                    "a datacenter resource could not be applied because it didn't contain an actual payload"
                );
                continue;
            };

            let dc = match crate::xds::Resource::try_decode(resource) {
                Ok(crate::xds::Resource::Datacenter(dc)) => dc,
                Ok(other) => {
                    tracing::error!(
                        type_url = other.type_url(),
                        "a datacenter resource could not be applied because the resource payload was not the correct type"
                    );
                    continue;
                }
                Err(error) => {
                    tracing::error!(%error, "a datacenter resource could not be applied because the resource payload could not be decoded");
                    continue;
                }
            };

            let parse_payload = || -> crate::Result<(IcaoCode, NodeAddress)> {
                use eyre::Context;
                let port = dc
                    .qcmp_port
                    .try_into()
                    .context("unable to parse datacenter QCMP port")?;
                let icao = dc
                    .icao_code
                    .parse()
                    .context("unable to parse datacenter ICAO")?;

                Ok((icao, NodeAddress { ip, port }))
            };

            let (icao, node_address) = match parse_payload() {
                Ok(dc) => dc,
                Err(error) => {
                    tracing::error!(%error, "failed to parse Datacenter protobuf");
                    continue;
                }
            };

            let mut dm = self.dm.lock();
            if let Some(eps) = dm.entries.get(&icao) {
                if eps.val.entries.contains_key(&node_address) {
                    continue;
                }
            }

            let op = dm.update(icao, dm.add_ctx(self.local_ip), |v, ctx| {
                v.add(node_address, ctx)
            });

            dm.apply(op);
            upserted = true;
        }

        if rmed || upserted {
            self.notify();
        }
    }

    #[inline]
    pub fn remove_datacenter(&self, ip: NodeIp) {
        if self.remove_ip(ip) {
            self.notify();
        }
    }

    #[inline]
    fn remove_ip(&self, ip: NodeIp) -> bool {
        let mut dm = self.dm.lock();
        for (key, entry) in &dm.entries {
            for addr in entry.val.entries.keys() {
                if addr.ip == ip {
                    let rm = entry.val.rm(*addr, entry.val.rm_ctx());
                    let rm_op = dm.up(*key, rm, self.local_ip);
                    dm.apply(rm_op);
                    return true;
                }
            }
        }

        false
    }

    #[inline]
    fn notify(&self) {
        let _ = self.tx.send(());
    }

    #[inline]
    pub fn watch(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    #[inline]
    pub fn get_by_ip(&self, ip: std::net::IpAddr) -> Option<Datacenter> {
        get_by_ip(&self.dm.lock(), ip)
    }
}

#[inline]
fn parse_crdt_key(s: &str) -> Option<(IcaoCode, NodeAddress)> {
    let (icao, ep) = s.split_once('-')?;
    let icao = icao.parse().ok()?;
    let endpoint = ep.parse().ok()?;

    Some((icao, endpoint))
}

#[inline]
fn parse_old_key(s: &str) -> Option<(IcaoCode, u16)> {
    let (icao, port) = s.split_once('-')?;
    Some((icao.parse().ok()?, port.parse().ok()?))
}

impl PartialEq for XdsDatacenterMap {
    fn eq(&self, other: &Self) -> bool {
        self.dm.lock().content_equal(&other.dm.lock())
    }
}

impl serde::Serialize for XdsDatacenterMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.dm.lock().serialize(serializer)
    }
}

#[cfg(test)]
impl Default for XdsDatacenterMap {
    fn default() -> Self {
        Self {
            dm: Default::default(),
            local_ip: NodeIp(std::net::Ipv6Addr::from_bits(0)),
            tx: tokio::sync::broadcast::channel(1).0,
        }
    }
}

pub enum PhoenixDatacenterMapOp {
    Clear,
    Add {
        icao: IcaoCode,
        ip: NodeIp,
        port: u16,
    },
    Rm {
        icao: IcaoCode,
        ip: NodeIp,
        port: u16,
    },
    RmAll {
        icao: IcaoCode,
    },
}

pub type PhoenixReceiver = tokio::sync::mpsc::Receiver<PhoenixDatacenterMapOp>;
pub type PhoenixSender = tokio::sync::mpsc::Sender<PhoenixDatacenterMapOp>;

#[inline]
fn get_by_ip(dm: &DatacenterMapCollection, ip: std::net::IpAddr) -> Option<Datacenter> {
    dm.entries.iter().find_map(|(key, entry)| {
        entry.val.entries.iter().find_map(|(addr, _)| {
            (addr.ip == ip).then_some(Datacenter {
                icao_code: *key,
                qcmp_port: addr.port,
            })
        })
    })
}

#[derive(Debug)]
pub struct PhoenixDatacenterMap {
    dm: parking_lot::Mutex<DatacenterMapCollection>,
    remote: parking_lot::Mutex<NodeIp>,
    tx: PhoenixSender,
}

impl PhoenixDatacenterMap {
    pub fn with_sender(tx: PhoenixSender) -> Self {
        Self {
            dm: Default::default(),
            remote: parking_lot::Mutex::new(NodeIp::default()),
            tx,
        }
    }

    pub fn new(capacity: usize) -> (Self, PhoenixReceiver) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        (
            Self {
                dm: Default::default(),
                remote: parking_lot::Mutex::new(NodeIp::default()),
                tx,
            },
            rx,
        )
    }

    #[inline]
    pub fn get_by_ip(&self, ip: std::net::IpAddr) -> Option<Datacenter> {
        get_by_ip(&self.dm.lock(), ip)
    }

    #[inline]
    pub fn reset(&self, snapshot: DatacenterMapCollection) {
        self.send(PhoenixDatacenterMapOp::Clear);

        for (key, val) in &snapshot.entries {
            let icao = *key;
            for node in val.val.entries.keys() {
                self.send(PhoenixDatacenterMapOp::Add {
                    icao,
                    ip: node.ip,
                    port: node.port,
                });
            }
        }

        *self.dm.lock() = snapshot;
    }

    pub fn apply_xds(&self, resources: Vec<XdsResource>, removed: &[String], remote: NodeIp) {
        let mut dc_map = self.dm.lock();

        // For now since proxies are only ever connected to one relay, we reset
        // the map if we connect to a new relay
        {
            let mut cur_remote = self.remote.lock();
            if *cur_remote != remote {
                self.send(PhoenixDatacenterMapOp::Clear);
                dc_map.remove_actor(*cur_remote, |_key| {});
                *cur_remote = remote;
            }
        }

        for rm in removed {
            let (icao, node_addr_or_port) = if let Some((icao, ep)) = parse_crdt_key(rm) {
                (icao, either::Left(ep))
            } else if let Some((icao, port)) = parse_old_key(rm) {
                (icao, either::Right(port))
            } else {
                continue;
            };

            if let Some(entry) = dc_map.entries.get(&icao) {
                if entry.val.len() == 1 {
                    let op = dc_map.rm(icao, dc_map.rm_ctx());
                    self.send(PhoenixDatacenterMapOp::RmAll { icao });
                    dc_map.apply(op);
                } else if let either::Left(node_addr) = node_addr_or_port {
                    let rm = entry.val.rm(node_addr, entry.val.rm_ctx());
                    let rm_op = dc_map.up(icao, rm, remote);
                    self.send(PhoenixDatacenterMapOp::Rm {
                        icao,
                        ip: node_addr.ip,
                        port: node_addr.port,
                    });
                    dc_map.apply(rm_op);
                }
            }
        }

        for res in resources {
            let Some(resource) = res.resource else {
                tracing::error!(
                    res.name,
                    "a datacenter resource could not be applied because it didn't contain an actual payload"
                );
                continue;
            };

            let dc = match crate::xds::Resource::try_decode(resource) {
                Ok(crate::xds::Resource::Datacenter(dc)) => dc,
                Ok(other) => {
                    tracing::error!(
                        type_url = other.type_url(),
                        "a datacenter resource could not be applied because the resource payload was not the correct type"
                    );
                    continue;
                }
                Err(error) => {
                    tracing::error!(%error, "a datacenter resource could not be applied because the resource payload could not be decoded");
                    continue;
                }
            };

            let host = match dc.host.parse() {
                Ok(host) => host,
                Err(error) => {
                    tracing::error!(%error, "failed to parse datacenter host");
                    continue;
                }
            };

            let parse_payload = || -> crate::Result<(IcaoCode, NodeAddress)> {
                use eyre::Context;
                let port = dc
                    .qcmp_port
                    .try_into()
                    .context("unable to parse datacenter QCMP port")?;
                let icao = dc
                    .icao_code
                    .parse()
                    .context("unable to parse datacenter ICAO")?;

                Ok((icao, NodeAddress { ip: host, port }))
            };

            let (icao, node_address) = match parse_payload() {
                Ok(dc) => dc,
                Err(error) => {
                    tracing::error!(%error, "failed to parse Datacenter protobuf");
                    continue;
                }
            };

            if let Some(eps) = dc_map.entries.get(&icao) {
                if eps.val.entries.contains_key(&node_address) {
                    continue;
                }
            }

            let op = dc_map.update(icao, dc_map.add_ctx(remote), |v, ctx| {
                v.add(node_address, ctx)
            });
            self.send(PhoenixDatacenterMapOp::Add {
                icao,
                ip: node_address.ip,
                port: node_address.port,
            });
            dc_map.apply(op);
        }
    }

    // #[inline]
    // fn apply_op(&self, op: DatacenterMapOp) {
    //     if let Err(error) = self.dm.lock().validate_op(&op) {
    //         tracing::error!(?error, "not applying DatacenterMap operation to Phoenix");
    //         return;
    //     }

    //     match &op {
    //         DatacenterMapOp::Rm { keyset, .. } => {
    //             for key in keyset {
    //                 self.send(PhoenixDatacenterMapOp::RmAll { icao: *key });
    //             }
    //         }
    //         DatacenterMapOp::Up { key, op, .. } => {
    //             let icao = *key;
    //             match op {
    //                 collections::orswot::Op::Add { members, .. } => {
    //                     for mem in members {
    //                         self.send(PhoenixDatacenterMapOp::Add {
    //                             icao,
    //                             ip: mem.ip,
    //                             port: mem.port,
    //                         });
    //                     }
    //                 }
    //                 collections::orswot::Op::Rm { members, .. } => {
    //                     for mem in members {
    //                         self.send(PhoenixDatacenterMapOp::Rm {
    //                             icao,
    //                             ip: mem.ip,
    //                             port: mem.port,
    //                         });
    //                     }
    //                 }
    //             }
    //         }
    //     }

    //     self.dm.lock().apply(op);
    // }

    #[inline]
    fn send(&self, op: PhoenixDatacenterMapOp) {
        if let Err(error) = self.tx.try_send(op) {
            match error {
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    static ONCE: std::sync::Once = std::sync::Once::new();

                    ONCE.call_once(|| {
                        tracing::error!("unable to send datacenter map change to Phoenix, the receiver was closed");
                    });
                }
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(
                        "unable to send datacenter map change to Phoenix, the receiver is full"
                    );
                }
            }
        }
    }
}

impl serde::Serialize for PhoenixDatacenterMap {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.dm.lock().serialize(serializer)
    }
}

impl PartialEq for PhoenixDatacenterMap {
    fn eq(&self, other: &Self) -> bool {
        self.dm.lock().content_equal(&other.dm.lock())
    }
}
