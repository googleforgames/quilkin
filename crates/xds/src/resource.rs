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

pub use crate::generated::quilkin::config::v1alpha1 as proto;
use prost_types::Any;

pub type Resource = Box<dyn ResourceType>;

pub trait ResourceType {
    fn name(&self) -> String;
    fn type_url(&self) -> &'static str;

    fn decode(&mut self, any: Any) -> Result<(), eyre::Error>;
    fn encode(&self) -> Result<Any, prost::EncodeError>;
}
