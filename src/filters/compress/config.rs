/*
 * Copyright 2021 Google LLC
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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::compressor::{Compressor, Snappy};
use super::quilkin::filters::compress::v1alpha1::{
    compress::{Action as ProtoAction, ActionValue, Mode as ProtoMode, ModeValue},
    Compress as ProtoConfig,
};

/// The library to use when compressing.
#[derive(Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[non_exhaustive]
pub enum Mode {
    // we only support one mode for now, but adding in the config option to
    // provide the option to expand for later.
    #[serde(rename = "SNAPPY")]
    Snappy,
}

impl Mode {
    pub(crate) fn as_compressor(&self) -> Box<dyn Compressor + Send + Sync> {
        match self {
            Self::Snappy => Box::from(Snappy {}),
        }
    }
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Snappy
    }
}

impl From<Mode> for ProtoMode {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Snappy => Self::Snappy,
        }
    }
}

impl From<ProtoMode> for Mode {
    fn from(mode: ProtoMode) -> Self {
        match mode {
            ProtoMode::Snappy => Self::Snappy,
        }
    }
}

impl From<Mode> for ModeValue {
    fn from(mode: Mode) -> Self {
        ModeValue {
            value: ProtoMode::from(mode) as i32,
        }
    }
}

/// Whether to do nothing, compress or decompress the packet.
#[derive(Clone, Copy, Deserialize, Debug, Eq, PartialEq, Serialize, JsonSchema)]
pub enum Action {
    #[serde(rename = "DO_NOTHING")]
    DoNothing,
    #[serde(rename = "COMPRESS")]
    Compress,
    #[serde(rename = "DECOMPRESS")]
    Decompress,
}

impl Default for Action {
    fn default() -> Self {
        Action::DoNothing
    }
}

impl From<Action> for ProtoAction {
    fn from(action: Action) -> Self {
        match action {
            Action::DoNothing => Self::DoNothing,
            Action::Compress => Self::Compress,
            Action::Decompress => Self::Decompress,
        }
    }
}

impl From<ProtoAction> for Action {
    fn from(action: ProtoAction) -> Self {
        match action {
            ProtoAction::DoNothing => Self::DoNothing,
            ProtoAction::Compress => Self::Compress,
            ProtoAction::Decompress => Self::Decompress,
        }
    }
}

impl From<Action> for ActionValue {
    fn from(action: Action) -> Self {
        Self {
            value: ProtoAction::from(action) as i32,
        }
    }
}

#[derive(Clone, Copy, Default, Deserialize, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[non_exhaustive]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    pub on_read: Action,
    pub on_write: Action,
}

impl From<Config> for ProtoConfig {
    fn from(config: Config) -> Self {
        Self {
            mode: Some(config.mode.into()),
            on_read: Some(config.on_read.into()),
            on_write: Some(config.on_write.into()),
        }
    }
}

impl From<ProtoConfig> for Config {
    fn from(p: ProtoConfig) -> Self {
        let mode = p
            .mode
            .map(|p| p.value())
            .map(Mode::from)
            .unwrap_or_default();

        let on_read = p
            .on_read
            .map(|p| p.value())
            .map(Action::from)
            .unwrap_or_default();

        let on_write = p
            .on_write
            .map(|p| p.value())
            .map(Action::from)
            .unwrap_or_default();

        Self {
            mode,
            on_read,
            on_write,
        }
    }
}
