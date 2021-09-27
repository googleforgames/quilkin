/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::convert::TryFrom;
use std::fmt;
use std::fmt::Formatter;
use std::net::SocketAddr;

use ipnetwork::IpNetwork;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{filters::ConvertProtoConfigError, map_proto_enum};

use super::quilkin::extensions::filters::firewall::v1alpha1::firewall::{
    Action as ProtoAction, PortRange as ProtoPortRange, Rule as ProtoRule,
};
use super::quilkin::extensions::filters::firewall::v1alpha1::Firewall as ProtoConfig;

/// Represents how a [Firewall] filter is configured for read and write
/// operations.
#[derive(Clone, Deserialize, Debug, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Config {
    pub on_read: Vec<Rule>,
    pub on_write: Vec<Rule>,
}

#[derive(Clone, Deserialize, Debug, PartialEq, Serialize)]
pub enum Action {
    /// Matching details will allow packets through.
    #[serde(rename = "ALLOW")]
    Allow,
    /// Matching details will block packets.
    #[serde(rename = "DENY")]
    Deny,
}

#[derive(Clone, Deserialize, Debug, PartialEq, Serialize)]
pub struct Rule {
    pub action: Action,
    /// ipv4 or ipv6 CIDR address.
    pub source: IpNetwork,
    pub ports: Vec<PortRange>,
}

impl Rule {
    /// Returns of the SocketAddress matches the provided CIDR address as well
    /// as at least one of the port ranges in the Rule.
    /// # Arguments
    ///
    /// * `address`: An ipv4 or ipv6 address and port.
    ///
    /// returns: bool
    ///
    pub fn contains(&self, address: SocketAddr) -> bool {
        if !self.source.contains(address.ip()) {
            return false;
        }

        self.ports
            .iter()
            .any(|range| range.contains(address.port()))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PortRange {
    pub min: u16,
    pub max: u16,
}

impl PortRange {
    /// Does this range contain a specific port value?
    ///
    /// # Arguments
    ///
    /// * `port`:
    ///
    /// returns: bool
    pub fn contains(&self, port: u16) -> bool {
        port >= self.min && port <= self.max
    }
}

impl Serialize for PortRange {
    /// Serialise the [PortRange] into a single digit if min and max are the same
    /// otherwise, serialise it to "min-max".
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.max == self.min {
            return serializer.serialize_str(self.min.to_string().as_str());
        }

        let range = format!("{}-{}", self.min, self.max);
        serializer.serialize_str(range.as_str())
    }
}

impl<'de> Deserialize<'de> for PortRange {
    /// Port ranges can be specified in yaml as either "10" as as single value
    /// or as "10-20" as a range, between a minimum and a maximum.
    /// This deserializes either format into a [PortRange].
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PortRangeVisitor;

        impl<'de> Visitor<'de> for PortRangeVisitor {
            type Value = PortRange;

            fn expecting(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
                f.write_str("A port range in the format of '10' or '10-20'")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match v.split_once('-') {
                    None => {
                        let value = v.parse::<u16>().map_err(de::Error::custom)?;
                        Ok(PortRange {
                            min: value,
                            max: value,
                        })
                    }
                    Some(split) => {
                        let min = split.0.parse::<u16>().map_err(de::Error::custom)?;
                        let max = split.1.parse::<u16>().map_err(de::Error::custom)?;

                        if min > max {
                            return Err(de::Error::custom(format!(
                                "min ({}) cannot be bigger than max ({})",
                                min, max
                            )));
                        }

                        Ok(PortRange { min, max })
                    }
                }
            }
        }

        deserializer.deserialize_str(PortRangeVisitor)
    }
}

impl TryFrom<ProtoConfig> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: ProtoConfig) -> Result<Self, Self::Error> {
        fn convert_port(range: &ProtoPortRange) -> Result<PortRange, ConvertProtoConfigError> {
            let min = u16::try_from(range.min).map_err(|err| {
                ConvertProtoConfigError::new(
                    format!("min too large: {}", err),
                    Some("port.min".into()),
                )
            })?;

            let max = u16::try_from(range.max).map_err(|err| {
                ConvertProtoConfigError::new(
                    format!("max too large: {}", err),
                    Some("port.max".into()),
                )
            })?;

            if min > max {
                return Err(ConvertProtoConfigError::new(
                    format!("min port ({}) is greater than the max port ({})", min, max),
                    Some("ports".into()),
                ));
            };

            Ok(PortRange { min, max })
        }

        fn convert_rule(rule: &ProtoRule) -> Result<Rule, ConvertProtoConfigError> {
            let action = map_proto_enum!(
                value = rule.action,
                field = "policy",
                proto_enum_type = ProtoAction,
                target_enum_type = Action,
                variants = [Allow, Deny]
            )?;

            let source = IpNetwork::try_from(rule.source.as_str()).map_err(|err| {
                ConvertProtoConfigError::new(
                    format!("invalid source: {:?}", err),
                    Some("source".into()),
                )
            })?;

            let ports = rule
                .ports
                .iter()
                .map(convert_port)
                .collect::<Result<Vec<PortRange>, ConvertProtoConfigError>>()?;

            Ok(Rule {
                action,
                source,
                ports,
            })
        }

        Ok(Config {
            on_read: p
                .on_read
                .iter()
                .map(convert_rule)
                .collect::<Result<Vec<Rule>, ConvertProtoConfigError>>()?,
            on_write: p
                .on_write
                .iter()
                .map(convert_rule)
                .collect::<Result<Vec<Rule>, ConvertProtoConfigError>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_yaml() {
        let yaml = "
on_read:
  - action: ALLOW
    source: 192.168.51.0/24
    ports:
       - 10
       - 1000-7000
on_write:
  - action: DENY
    source: 192.168.75.0/24
    ports:
       - 7000
        ";

        let config: Config = serde_yaml::from_str(yaml).unwrap();

        let rule1 = config.on_read[0].clone();
        assert_eq!(rule1.action, Action::Allow);
        assert_eq!(rule1.source, "192.168.51.0/24".parse().unwrap());
        assert_eq!(2, rule1.ports.len());
        assert_eq!(10, rule1.ports[0].min);
        assert_eq!(10, rule1.ports[0].max);
        assert_eq!(1000, rule1.ports[1].min);
        assert_eq!(7000, rule1.ports[1].max);

        let rule2 = config.on_write[0].clone();
        assert_eq!(rule2.action, Action::Deny);
        assert_eq!(rule2.source, "192.168.75.0/24".parse().unwrap());
        assert_eq!(1, rule2.ports.len());
        assert_eq!(7000, rule2.ports[0].min);
        assert_eq!(7000, rule2.ports[0].max);
    }

    #[test]
    fn portrange_contains() {
        let range = PortRange { min: 10, max: 100 };
        assert!(range.contains(10));
        assert!(range.contains(100));
        assert!(range.contains(50));
        assert!(!range.contains(200));
        assert!(!range.contains(5));
    }

    #[test]
    fn convert() {
        let proto_config = ProtoConfig {
            on_read: vec![ProtoRule {
                action: ProtoAction::Allow as i32,
                source: "192.168.75.0/24".into(),
                ports: vec![ProtoPortRange { min: 10, max: 100 }],
            }],
            on_write: vec![ProtoRule {
                action: ProtoAction::Deny as i32,
                source: "192.168.124.0/24".into(),
                ports: vec![ProtoPortRange { min: 50, max: 50 }],
            }],
        };

        let config = Config::try_from(proto_config).unwrap();

        let rule1 = config.on_read[0].clone();
        assert_eq!(rule1.action, Action::Allow);
        assert_eq!(rule1.source, "192.168.75.0/24".parse().unwrap());
        assert_eq!(1, rule1.ports.len());
        assert_eq!(10, rule1.ports[0].min);
        assert_eq!(100, rule1.ports[0].max);

        let rule2 = config.on_write[0].clone();
        assert_eq!(rule2.action, Action::Deny);
        assert_eq!(rule2.source, "192.168.124.0/24".parse().unwrap());
        assert_eq!(1, rule2.ports.len());
        assert_eq!(50, rule2.ports[0].min);
        assert_eq!(50, rule2.ports[0].max);
    }

    #[test]
    fn rule_contains() {
        let rule = Rule {
            action: Action::Allow,
            source: "192.168.75.0/24".parse().unwrap(),
            ports: vec![PortRange { min: 10, max: 100 }],
        };

        assert!(rule.contains("192.168.75.10:50".parse().unwrap()));
        assert!(rule.contains("192.168.75.10:100".parse().unwrap()));
        assert!(rule.contains("192.168.75.10:10".parse().unwrap()));

        assert!(!rule.contains("192.168.75.10:5".parse().unwrap()));
        assert!(!rule.contains("192.168.75.10:1000".parse().unwrap()));
        assert!(!rule.contains("192.168.76.10:40".parse().unwrap()));
    }
}
