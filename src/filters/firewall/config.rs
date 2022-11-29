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

use std::{convert::TryFrom, fmt, fmt::Formatter, net::SocketAddr, ops::Range};

use ipnetwork::IpNetwork;
use schemars::JsonSchema;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::filters::ConvertProtoConfigError;

use super::proto;

/// Represents how a Firewall filter is configured for read and write
/// operations.
#[derive(Clone, Deserialize, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[non_exhaustive]
pub struct Config {
    pub on_read: Vec<Rule>,
    pub on_write: Vec<Rule>,
}

/// Whether or not a matching [Rule] should Allow or Deny access
#[derive(Clone, Deserialize, Debug, Eq, PartialEq, Serialize, JsonSchema)]
pub enum Action {
    /// Matching rules will allow packets through.
    #[serde(rename = "ALLOW")]
    Allow,
    /// Matching rules will block packets.
    #[serde(rename = "DENY")]
    Deny,
}

impl From<Action> for proto::firewall::Action {
    fn from(action: Action) -> Self {
        match action {
            Action::Allow => Self::Allow,
            Action::Deny => Self::Deny,
        }
    }
}

impl From<proto::firewall::Action> for Action {
    fn from(action: proto::firewall::Action) -> Self {
        match action {
            proto::firewall::Action::Allow => Self::Allow,
            proto::firewall::Action::Deny => Self::Deny,
        }
    }
}

/// Combination of CIDR range, port range and action to take.
#[derive(Clone, Deserialize, Debug, Eq, PartialEq, Serialize, JsonSchema)]
pub struct Rule {
    pub action: Action,
    /// ipv4 or ipv6 CIDR address.
    #[schemars(with = "String")]
    pub source: IpNetwork,
    pub ports: Vec<PortRange>,
}

impl Rule {
    /// Returns `true` if `address` matches the provided CIDR address as well
    /// as at least one of the port ranges in the [Rule].
    ///
    /// # Examples
    /// ```
    /// use quilkin::filters::firewall::{Action, PortRange};
    ///
    /// let rule = quilkin::filters::firewall::Rule {
    ///    action: Action::Allow,
    ///    source: "192.168.75.0/24".parse().unwrap(),
    ///    ports: vec![PortRange::new(10, 100).unwrap()],
    /// };
    ///
    /// let ip = [192, 168, 75, 10];
    /// assert!(rule.contains((ip, 50).into()));
    /// assert!(rule.contains((ip, 99).into()));
    /// assert!(rule.contains((ip, 10).into()));
    ///
    /// assert!(!rule.contains((ip, 5).into()));
    /// assert!(!rule.contains((ip, 1000).into()));
    /// assert!(!rule.contains(([192, 168, 76, 10], 40).into()));
    /// ```
    pub fn contains(&self, address: SocketAddr) -> bool {
        if !self.source.contains(address.ip()) {
            return false;
        }

        self.ports
            .iter()
            .any(|range| range.contains(&address.port()))
    }
}

impl From<Rule> for proto::firewall::Rule {
    fn from(rule: Rule) -> Self {
        Self {
            action: proto::firewall::Action::from(rule.action) as i32,
            source: rule.source.to_string(),
            ports: rule.ports.into_iter().map(From::from).collect(),
        }
    }
}

/// Invalid min and max values for a [PortRange].
#[derive(Debug, thiserror::Error)]
pub enum PortRangeError {
    #[error("invalid port range: min {min:?} is greater than or equal to max {max:?}")]
    InvalidRange { min: u16, max: u16 },
}

/// Range of matching ports that are configured against a [Rule].
#[derive(Clone, Debug, Eq, PartialEq, JsonSchema)]
pub struct PortRange(Range<u16>);

impl PortRange {
    /// Creates a new [PortRange], where min is inclusive, max is exclusive.
    /// [Result] will be a [PortRangeError] if `min >= max`.
    pub fn new(min: u16, max: u16) -> Result<Self, PortRangeError> {
        if min >= max {
            return Err(PortRangeError::InvalidRange { min, max });
        }

        Ok(Self(Range {
            start: min,
            end: max,
        }))
    }

    /// Returns true if the range contain the given `port`.
    pub fn contains(&self, port: &u16) -> bool {
        self.0.contains(port)
    }
}

impl From<PortRange> for proto::firewall::PortRange {
    fn from(range: PortRange) -> Self {
        Self {
            min: range.0.start.into(),
            max: range.0.end.into(),
        }
    }
}

impl Serialize for PortRange {
    /// Serialise the [PortRange] into a single digit if min and max are the same
    /// otherwise, serialise it to "min-max".
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if self.0.start == (self.0.end - 1) {
            return serializer.serialize_str(self.0.start.to_string().as_str());
        }

        let range = format!("{}-{}", self.0.start, self.0.end);
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
                        PortRange::new(value, value + 1).map_err(de::Error::custom)
                    }
                    Some(split) => {
                        let start = split.0.parse::<u16>().map_err(de::Error::custom)?;
                        let end = split.1.parse::<u16>().map_err(de::Error::custom)?;
                        PortRange::new(start, end).map_err(de::Error::custom)
                    }
                }
            }
        }

        deserializer.deserialize_str(PortRangeVisitor)
    }
}

impl From<Config> for proto::Firewall {
    fn from(config: Config) -> Self {
        Self {
            on_read: config.on_read.into_iter().map(From::from).collect(),
            on_write: config.on_write.into_iter().map(From::from).collect(),
        }
    }
}

impl TryFrom<proto::Firewall> for Config {
    type Error = ConvertProtoConfigError;

    fn try_from(p: proto::Firewall) -> Result<Self, Self::Error> {
        fn convert_port(
            range: &proto::firewall::PortRange,
        ) -> Result<PortRange, ConvertProtoConfigError> {
            let min = u16::try_from(range.min).map_err(|err| {
                ConvertProtoConfigError::new(
                    format!("min too large: {err}"),
                    Some("port.min".into()),
                )
            })?;

            let max = u16::try_from(range.max).map_err(|err| {
                ConvertProtoConfigError::new(
                    format!("max too large: {err}"),
                    Some("port.max".into()),
                )
            })?;

            PortRange::new(min, max)
                .map_err(|err| ConvertProtoConfigError::new(format!("{err}"), Some("ports".into())))
        }

        fn convert_rule(rule: &proto::firewall::Rule) -> Result<Rule, ConvertProtoConfigError> {
            let action = Action::from(rule.action());
            let source = IpNetwork::try_from(rule.source.as_str()).map_err(|err| {
                ConvertProtoConfigError::new(
                    format!("invalid source: {err:?}"),
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
        assert_eq!(10, rule1.ports[0].0.start);
        assert_eq!(11, rule1.ports[0].0.end);
        assert_eq!(1000, rule1.ports[1].0.start);
        assert_eq!(7000, rule1.ports[1].0.end);

        let rule2 = config.on_write[0].clone();
        assert_eq!(rule2.action, Action::Deny);
        assert_eq!(rule2.source, "192.168.75.0/24".parse().unwrap());
        assert_eq!(1, rule2.ports.len());
        assert_eq!(7000, rule2.ports[0].0.start);
        assert_eq!(7001, rule2.ports[0].0.end);
    }

    #[test]
    fn portrange_contains() {
        let range = PortRange::new(10, 100).unwrap();
        assert!(range.contains(&10));
        assert!(!range.contains(&100));
        assert!(range.contains(&50));
        assert!(!range.contains(&200));
        assert!(!range.contains(&5));

        // single value
        let single = PortRange::new(10, 11).unwrap();
        assert!(single.contains(&10));
        assert!(!single.contains(&11));
    }

    #[test]
    fn convert() {
        let proto_config = proto::Firewall {
            on_read: vec![proto::firewall::Rule {
                action: proto::firewall::Action::Allow as i32,
                source: "192.168.75.0/24".into(),
                ports: vec![proto::firewall::PortRange { min: 10, max: 100 }],
            }],
            on_write: vec![proto::firewall::Rule {
                action: proto::firewall::Action::Deny as i32,
                source: "192.168.124.0/24".into(),
                ports: vec![proto::firewall::PortRange { min: 50, max: 51 }],
            }],
        };

        let config = Config::try_from(proto_config).unwrap();

        let rule1 = config.on_read[0].clone();
        assert_eq!(rule1.action, Action::Allow);
        assert_eq!(rule1.source, "192.168.75.0/24".parse().unwrap());
        assert_eq!(1, rule1.ports.len());
        assert_eq!(10, rule1.ports[0].0.start);
        assert_eq!(100, rule1.ports[0].0.end);

        let rule2 = config.on_write[0].clone();
        assert_eq!(rule2.action, Action::Deny);
        assert_eq!(rule2.source, "192.168.124.0/24".parse().unwrap());
        assert_eq!(1, rule2.ports.len());
        assert_eq!(50, rule2.ports[0].0.start);
        assert_eq!(51, rule2.ports[0].0.end);
    }

    #[test]
    fn rule_contains() {
        let rule = Rule {
            action: Action::Allow,
            source: "192.168.75.0/24".parse().unwrap(),
            ports: vec![PortRange::new(10, 100).unwrap()],
        };

        let ip = [192, 168, 75, 10];
        assert!(rule.contains((ip, 50).into()));
        assert!(rule.contains((ip, 99).into()));
        assert!(rule.contains((ip, 10).into()));

        assert!(!rule.contains((ip, 5).into()));
        assert!(!rule.contains((ip, 1000).into()));
        assert!(!rule.contains(([192, 168, 76, 10], 40).into()));
    }
}
