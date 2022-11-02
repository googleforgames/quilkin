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

crate::include_proto!("quilkin.filters.concatenate.v1alpha1");

mod config;

use crate::filters::prelude::*;

use self::quilkin::filters::concatenate::v1alpha1 as proto;
pub use config::{Config, Strategy};

/// The `Concatenate` adds a metadata value to either the beginning or end of
/// each UDP packet that passes through. This is commonly used to provide an
/// auth token to each packet, so they can be routed appropriately.
pub struct Concatenate {
    config: Config,
}

impl Concatenate {
    pub fn new(config: Config) -> Self {
        Concatenate { config }
    }

    fn concatenate(
        &self,
        metadata: &crate::Metadata,
        strategy: Strategy,
        contents: &mut Vec<u8>,
    ) -> Option<()> {
        if strategy == Strategy::DoNothing {
            return Some(());
        }

        let iter = metadata.resolve_to_bytes(&self.config.value)?.into_iter();
        match strategy {
            Strategy::Append => contents.extend(iter),
            Strategy::Prepend => drop(contents.splice(..0, iter)),
            Strategy::DoNothing => {}
        }

        Some(())
    }
}

impl Filter for Concatenate {
    fn read(&self, ctx: &mut ReadContext) -> Option<()> {
        self.concatenate(&ctx.metadata, self.config.on_read, &mut ctx.contents)
    }

    fn write(&self, ctx: &mut WriteContext) -> Option<()> {
        self.concatenate(&ctx.metadata, self.config.on_write, &mut ctx.contents)
    }
}

impl StaticFilter for Concatenate {
    const NAME: &'static str = "quilkin.filters.concatenate.v1alpha1.Concatenate";
    type Configuration = Config;
    type BinaryConfiguration = proto::Concatenate;

    fn try_from_config(config: Option<Self::Configuration>) -> Result<Self, Error> {
        Ok(Concatenate::new(Self::ensure_config_exists(config)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{endpoint::EndpointAddress, metadata::Symbol};

    #[test]
    fn concatenate_dynamic_variable() {
        const CONTENTS: &[u8] = b"gamedata";
        let concatenate = Concatenate::new(Config {
            on_read: Strategy::DoNothing,
            on_write: Strategy::Append,
            value: Symbol::reference("quilkin.dev/computed/timestamp/now"),
        });

        let mut ctx = WriteContext {
            endpoint: EndpointAddress::UNSPECIFIED.into(),
            source: EndpointAddress::UNSPECIFIED,
            dest: EndpointAddress::UNSPECIFIED,
            contents: CONTENTS.to_vec(),
            metadata: <_>::default(),
        };

        concatenate.write(&mut ctx).unwrap();

        assert_eq!(
            CONTENTS.len() + std::mem::size_of::<i64>(),
            ctx.contents.len()
        );
    }
}
