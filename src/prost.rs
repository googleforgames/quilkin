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
                .filter_map(|(k, v)| v.kind.map(value_from_kind).map(|v| (k.into(), v)))
                .collect(),
        ),
    }
}

pub fn struct_from_yaml(value: Value) -> Option<prost_types::Struct> {
    match from_yaml(value) {
        prost_types::Value {
            kind: Some(Kind::StructValue(r#struct)),
        } => Some(r#struct),
        _ => None,
    }
}

pub fn from_yaml(value: Value) -> prost_types::Value {
    prost_types::Value {
        kind: Some(match value {
            Value::Null => Kind::NullValue(<_>::default()),
            Value::Bool(v) => Kind::BoolValue(v),
            // as_f64 never returns None, so unwrap is safe here.
            Value::Number(v) => Kind::NumberValue(v.as_f64().unwrap()),
            Value::String(v) => Kind::StringValue(v),
            Value::Sequence(v) => Kind::ListValue(prost_types::ListValue {
                values: v.into_iter().map(from_yaml).collect(),
            }),
            Value::Mapping(v) => Kind::StructValue(prost_types::Struct {
                fields: v
                    .into_iter()
                    .filter_map(|(key, value)| {
                        let key = if let Value::String(value) = key {
                            value
                        } else {
                            return None;
                        };

                        Some((key, from_yaml(value)))
                    })
                    .collect(),
            }),
        }),
    }
}
