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

//! Extensions to `prost` and related crates.

use prost_types::value::Kind;
use serde_yaml::Value;

pub fn mapping_from_kind(kind: Kind) -> Option<serde_yaml::Mapping> {
    match value_from_kind(kind) {
        Value::Mapping(mapping) => Some(mapping),
        _ => None,
    }
}

pub fn value_from_kind(kind: Kind) -> Value {
    match kind {
        Kind::NullValue(_) => Value::Null,
        Kind::BoolValue(v) => Value::Bool(v),
        Kind::NumberValue(v) => Value::Number(serde_yaml::Number::from(v)),
        Kind::StringValue(v) => Value::String(v),
        Kind::ListValue(v) => Value::Sequence(
            v.values
                .into_iter()
                .filter_map(|v| v.kind)
                .map(value_from_kind)
                .collect(),
        ),
        Kind::StructValue(v) => Value::Mapping(
            v.fields
                .into_iter()
                .filter(|(_, v)| v.kind.is_some())
                .map(|(k, v)| (k.into(), value_from_kind(v.kind.unwrap())))
                .collect(),
        ),
    }
}
