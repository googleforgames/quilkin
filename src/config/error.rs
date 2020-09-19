use crate::extensions::Error as FilterRegistryError;
use std::fmt::{self, Display, Formatter};

/// Validation failure for a Config
#[derive(Debug, PartialEq)]
pub enum ValidationError {
    NotUnique(String),
    FilterInvalid(FilterRegistryError),
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::NotUnique(field) => write!(f, "field {} is not unique", field),
            ValidationError::FilterInvalid(reason) => {
                write!(f, "filter configuration is invalid: {}", reason)
            }
        }
    }
}
