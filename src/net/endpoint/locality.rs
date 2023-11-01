/*
 * Copyright 2022 Google LLC
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

use serde::{Deserialize, Serialize};

/// The location of an [`Endpoint`][super::Endpoint].
#[derive(
    Clone,
    Default,
    Debug,
    Hash,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    schemars::JsonSchema,
    PartialOrd,
    Ord,
)]
pub struct Locality {
    /// The geographic region.
    #[serde(default)]
    pub region: String,
    /// The zone within the `region`, if applicable.
    #[serde(default)]
    pub zone: String,
    /// The subzone within the `zone`, if applicable.
    #[serde(default)]
    pub sub_zone: String,
}

impl Locality {
    pub fn new(
        region: impl Into<String>,
        zone: impl Into<String>,
        sub_zone: impl Into<String>,
    ) -> Self {
        Self {
            region: region.into(),
            zone: zone.into(),
            sub_zone: sub_zone.into(),
        }
    }

    pub fn region(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            ..Self::default()
        }
    }

    pub fn zone(mut self, zone: impl Into<String>) -> Self {
        self.zone = zone.into();
        self
    }

    pub fn colon_separated_string(&self) -> String {
        let mut string = String::from(&*self.region);

        if !self.zone.is_empty() {
            string += ":";
            string += &*self.zone;
        }

        if !self.sub_zone.is_empty() {
            string += ":";
            string += &*self.sub_zone;
        }

        string
    }

    pub fn sub_zone(mut self, sub_zone: impl Into<String>) -> Self {
        self.sub_zone = sub_zone.into();
        self
    }
}

impl std::fmt::Display for Locality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.colon_separated_string().fmt(f)
    }
}

impl std::str::FromStr for Locality {
    type Err = eyre::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let vec: Vec<_> = input.split(':').collect();

        Ok(match vec.len() {
            1 => Self {
                region: vec[0].into(),
                ..<_>::default()
            },
            2 => Self {
                region: vec[0].into(),
                zone: vec[1].into(),
                ..<_>::default()
            },
            3 => Self {
                region: vec[0].into(),
                zone: vec[1].into(),
                sub_zone: vec[2].into(),
            },
            _ => return Err(eyre::eyre!("invalid locality identifier")),
        })
    }
}

impl From<crate::net::cluster::proto::Locality> for Locality {
    fn from(value: crate::net::cluster::proto::Locality) -> Self {
        Self {
            region: value.region,
            zone: value.zone,
            sub_zone: value.sub_zone,
        }
    }
}

impl From<Locality> for crate::net::cluster::proto::Locality {
    fn from(value: Locality) -> Self {
        Self {
            region: value.region,
            zone: value.zone,
            sub_zone: value.sub_zone,
        }
    }
}
