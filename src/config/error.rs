use crate::extensions::Error as FilterRegistryError;
use std::fmt::{self, Display, Formatter};

/// Validation failure for a Config
#[derive(Debug, PartialEq)]
pub enum ValidationError {
    NotUnique(String),
    EmptyList(String),
    ValueInvalid(String, Option<Vec<String>>),
    FilterInvalid(FilterRegistryError),
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::NotUnique(field) => write!(f, "field {} is not unique", field),
            ValidationError::EmptyList(field) => write!(f, "field {} is cannot be an empty", field),
            ValidationError::ValueInvalid(field, examples) => write!(
                f,
                "{} has an invalid value {}",
                field,
                examples.as_ref().map(|v| v.join(",")).unwrap_or_default()
            ),
            ValidationError::FilterInvalid(reason) => {
                write!(f, "filter configuration is invalid: {}", reason)
            }
        }
    }
}
