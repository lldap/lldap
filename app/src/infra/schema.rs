use anyhow::Result;
use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeType {
    String,
    Integer,
    DateTime,
    Jpeg,
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
            _ => Err(()),
        }
    }
}

// Macro to generate traits for converting between AttributeType and the
// graphql generated equivalents.
#[macro_export]
macro_rules! convert_attribute_type {
    ($source_type:ty) => {
        impl From<$source_type> for AttributeType {
            fn from(value: $source_type) -> Self {
                match value {
                    <$source_type>::STRING => AttributeType::String,
                    <$source_type>::INTEGER => AttributeType::Integer,
                    <$source_type>::DATE_TIME => AttributeType::DateTime,
                    <$source_type>::JPEG_PHOTO => AttributeType::Jpeg,
                    _ => panic!("Unknown attribute type"),
                }
            }
        }

        impl From<AttributeType> for $source_type {
            fn from(value: AttributeType) -> Self {
                match value {
                    AttributeType::String => <$source_type>::STRING,
                    AttributeType::Integer => <$source_type>::INTEGER,
                    AttributeType::DateTime => <$source_type>::DATE_TIME,
                    AttributeType::Jpeg => <$source_type>::JPEG_PHOTO,
                }
            }
        }
    };
}

#[derive(Clone, PartialEq, Eq)]
pub struct Attribute {
  pub name: String,
  pub value: Vec<String>,
  pub attribute_type: AttributeType,
  pub is_list: bool,
  pub is_editable: bool,
  pub is_hardcoded: bool,
}

// Macro to generate traits for converting between AttributeType and the
// graphql generated equivalents.
#[macro_export]
macro_rules! combine_schema_and_values {
    ($schema_list:ident, $value_list:ident, $output_list:ident) => {
        let set_attributes = value_list.clone();
        let mut attribute_schema = schema_list.clone();
        attribute_schema.retain(|schema| !schema.is_hardcoded);
        let $output_list = attribute_schema.into_iter().map(|schema| {
            Attribute {
                name: schema.name.clone(),
                value: set_attributes.iter().find(|attribute_value| attribute_value.name == schema.name).unwrap().value.clone(),
                attribute_type: AttributeType::from(schema.attribute_type),
                is_list: schema.is_list,
            }
        }).collect();
    };
}