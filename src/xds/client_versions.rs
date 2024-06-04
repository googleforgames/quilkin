use std::{collections::HashMap, fmt};

/// Keeps track of what resource versions a particular client has
pub struct ClientTracker {
    node_id: String,
    clusters: HashMap<Option<Locality>, EndpointSetVersion>,
}

/// The resources and versions that were sent in a delta response, when acked
/// this is used with `ClientVersions::ack` to update the set of resources on
/// the client has
pub enum AwaitingAck {
    FilterChain,
    Cluster {
        updated: Vec<(Option<Locality>, EndpointSetVersion)>,
        remove_none: bool,
    },
    Datacenter,
}

impl ::xds::config::ClientTracker<Ack = AwaitingAck> for ClientTracker {
    fn track_client(node_id: String) -> Self {
        Self {
            node_id,
            clusters: HashMap::new(),
        }
    }

    /// Updates the versions of the client following an `ACK` by the client for
    /// a set of resources
    #[inline]
    pub fn ack(&mut self, ack: AwaitingAck) {
        match ack {
            AwaitingAck::Datacenter | AwaitingAck::FilterChain => {}
            AwaitingAck::Cluster {
                updated,
                remove_none,
            } => {
                for (locality, version) in updated {
                    self.clusters.insert(locality, version);
                }

                if remove_none {
                    self.clusters.remove(&None);
                }
            }
        }
    }

    #[inline]
    pub fn remove(&mut self, name: String) {
        let Self::Cluster(map) = self else {
            return;
        };

        let locality = if name.is_empty() {
            None
        } else {
            match name.parse() {
                Ok(l) => Some(l),
                Err(err) => {
                    tracing::error!(error = %err, name, "Failed to parse locality");
                    return;
                }
            }
        };
        map.remove(&locality);
    }

    /// Resets the client versions to those specified by the client itself
    #[inline]
    pub fn reset(&mut self, versions: HashMap<String, String>) -> crate::Result<()> {
        let Self::Cluster(map) = self else {
            return Ok(());
        };

        map.clear();

        for (k, v) in versions {
            let locality = if k.is_empty() { None } else { Some(k.parse()?) };
            let version = v.parse()?;

            map.insert(locality, version);
        }

        Ok(())
    }
}
