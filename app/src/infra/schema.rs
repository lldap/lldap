use anyhow::Result;
use std::{fmt::Display, str::FromStr};
use validator::ValidationError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeType {
    String,
    Integer,
    DateTime,
    Jpeg,
    Boolean,
}

impl Display for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for AttributeType {
    type Err = ();
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "String" => Ok(AttributeType::String),
            "Integer" => Ok(AttributeType::Integer),
            "DateTime" => Ok(AttributeType::DateTime),
            "Jpeg" => Ok(AttributeType::Jpeg),
            "Boolean" => Ok(AttributeType::Boolean),
            _ => Err(()),
        }
    }
}

// Macro to generate traits for converting between AttributeType and the
// graphql generated equivalents.
#[macro_export]
macro_rules! convert_attribute_type {
    ($source_type:ty) => {
        impl From<$source_type> for $crate::infra::schema::AttributeType {
            fn from(value: $source_type) -> Self {
                match value {
                    <$source_type>::STRING => $crate::infra::schema::AttributeType::String,
                    <$source_type>::INTEGER => $crate::infra::schema::AttributeType::Integer,
                    <$source_type>::DATE_TIME => $crate::infra::schema::AttributeType::DateTime,
                    <$source_type>::JPEG_PHOTO => $crate::infra::schema::AttributeType::Jpeg,
                    <$source_type>::BOOLEAN => $crate::infra::schema::AttributeType::Boolean,
                    _ => panic!("Unknown attribute type"),
                }
            }
        }

        impl From<$crate::infra::schema::AttributeType> for $source_type {
            fn from(value: $crate::infra::schema::AttributeType) -> Self {
                match value {
                    $crate::infra::schema::AttributeType::String => <$source_type>::STRING,
                    $crate::infra::schema::AttributeType::Integer => <$source_type>::INTEGER,
                    $crate::infra::schema::AttributeType::DateTime => <$source_type>::DATE_TIME,
                    $crate::infra::schema::AttributeType::Jpeg => <$source_type>::JPEG_PHOTO,
                    $crate::infra::schema::AttributeType::Boolean => <$source_type>::BOOLEAN,
                }
            }
        }
    };
}

pub fn validate_attribute_type(attribute_type: &str) -> Result<(), ValidationError> {
    AttributeType::from_str(attribute_type)
        .map_err(|_| ValidationError::new("Invalid attribute type"))?;
    Ok(())
}
