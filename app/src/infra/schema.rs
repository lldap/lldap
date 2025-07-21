use serde::{Deserialize, Serialize};
use std::fmt::Display;
use validator::ValidationError;

#[derive(Deserialize, Serialize, Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum AttributeType {
    String,
    Integer,
    DateTime,
    JpegPhoto,
}

impl Display for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn validate_attribute_type(attribute_type: &str) -> Result<(), ValidationError> {
    serde_json::from_str::<AttributeType>(attribute_type)
        .map_err(|_| ValidationError::new("Invalid attribute type"))?;
    Ok(())
}
