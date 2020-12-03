use crate::extensions::Error as FilterRegistryError;
use std::fmt::{self, Display, Formatter};

#[derive(Debug, PartialEq)]
pub struct ValueInvalidArgs {
    pub field: String,
    pub clarification: Option<String>,
    pub examples: Option<Vec<String>>,
}

/// Validation failure for a Config
#[derive(Debug, PartialEq)]
pub enum ValidationError {
    NotUnique(String),
    EmptyList(String),
    ValueInvalid(ValueInvalidArgs),
    FilterInvalid(FilterRegistryError),
}

impl Display for ValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::NotUnique(field) => write!(f, "field {} is not unique", field),
            ValidationError::EmptyList(field) => write!(f, "field {} is cannot be an empty", field),
            ValidationError::ValueInvalid(args) => write!(
                f,
                "{} has an invalid value{}{}",
                args.field,
                args.clarification
                    .as_ref()
                    .map(|v| format!(": {}", v))
                    .unwrap_or_default(),
                args.examples
                    .as_ref()
                    .map(|v| format!("examples: {}", v.join(",")))
                    .unwrap_or_default()
            ),
            ValidationError::FilterInvalid(reason) => {
                write!(f, "filter configuration is invalid: {}", reason)
            }
        }
    }
}
