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

use once_cell::sync::Lazy;

use super::Value;

static INTERNER: Lazy<lasso::ThreadedRodeo> = Lazy::new(lasso::ThreadedRodeo::new);

/// A key in the metadata table.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Hash, Ord, schemars::JsonSchema)]
pub struct Key(#[schemars(with = "String")] lasso::Spur);

impl Key {
    pub fn new<A: AsRef<str>>(key: A) -> Self {
        Self(INTERNER.get_or_intern(key.as_ref()))
    }

    pub fn from_static(key: &'static str) -> Self {
        Self(INTERNER.get_or_intern_static(key))
    }

    pub fn from_raw(spur: lasso::Spur) -> Self {
        Self(spur)
    }
}

impl From<lasso::Spur> for Key {
    fn from(spur: lasso::Spur) -> Self {
        Self::from_raw(spur)
    }
}

impl From<String> for Key {
    fn from(string: String) -> Self {
        Self::new(string)
    }
}

impl From<&'_ str> for Key {
    fn from(string: &str) -> Self {
        Self::new(string)
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        INTERNER.resolve(&self.0).fmt(f)
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        INTERNER.resolve(&self.0).fmt(f)
    }
}

impl<'de> serde::Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        std::borrow::Cow::<'de, str>::deserialize(deserializer).map(Self::new)
    }
}

impl serde::Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

/// A literal value or a reference to a value in a metadata map.
#[derive(
    Clone,
    Debug,
    PartialEq,
    PartialOrd,
    serde::Serialize,
    serde::Deserialize,
    Eq,
    Ord,
    schemars::JsonSchema,
)]
#[serde(untagged)]
pub enum Symbol {
    Reference(Reference),
    Literal(Value),
}

impl Symbol {
    /// Creates a reference symbol referring to a variable coming
    /// from metadata.
    pub fn reference(key: impl AsRef<str>) -> Self {
        Self::Reference(Reference::new(key.as_ref()))
    }

    /// Creates a reference symbol referring to an existing `key`.
    pub fn raw_reference(key: Key) -> Self {
        Self::Reference(Reference::raw(key))
    }

    /// Creates a literal value symbol.
    pub fn literal(value: impl Into<Value>) -> Self {
        Self::Literal(value.into())
    }

    /// Maps the symbol to its inner literal value, if present.
    pub fn as_literal(&self) -> Option<&Value> {
        match self {
            Self::Literal(value) => Some(value),
            Self::Reference(_) => None,
        }
    }

    /// Maps the symbol to its inner reference, if present.
    pub fn as_reference(&self) -> Option<&Reference> {
        match self {
            Self::Literal(_) => None,
            Self::Reference(reference) => Some(reference),
        }
    }
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Literal(literal) => literal.fmt(f),
            Self::Reference(key) => key.fmt(f),
        }
    }
}

impl From<Value> for Symbol {
    fn from(value: Value) -> Self {
        Self::Literal(value)
    }
}

impl From<Reference> for Symbol {
    fn from(reference: Reference) -> Self {
        Self::Reference(reference)
    }
}

/// Reference to a metadata value.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, schemars::JsonSchema)]
#[schemars(transparent)]
pub struct Reference {
    key: Key,
}

impl Reference {
    /// Creates a new reference to a value in metadata.
    pub fn new<A: AsRef<str>>(key: A) -> Self {
        Self::raw(Key::new(key.as_ref()))
    }

    /// Creates a new reference to a value in metadata.
    pub fn raw(key: Key) -> Self {
        Self { key }
    }

    /// Returns the inner `key`.
    pub fn key(self) -> Key {
        self.key
    }
}

impl std::fmt::Display for Reference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "${}", self.key)
    }
}

impl serde::Serialize for Reference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Reference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;

        if let Some(string) = string.strip_prefix('$') {
            Ok(Self::new(string))
        } else {
            Err(<D::Error as serde::de::Error>::custom(
                "references are required to start with `$`",
            ))
        }
    }
}
