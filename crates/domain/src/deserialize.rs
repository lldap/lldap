use crate::types::{AttributeType, AttributeValue, JpegPhoto};
use anyhow::{Context as AnyhowContext, Result, bail};

pub fn deserialize_attribute_value(
    value: &[String],
    typ: AttributeType,
    is_list: bool,
) -> Result<AttributeValue> {
    if !is_list && value.len() != 1 {
        bail!("Attribute is not a list, but multiple values were provided",);
    }
    let parse_int = |value: &String| -> Result<i64> {
        value
            .parse::<i64>()
            .with_context(|| format!("Invalid integer value {value}"))
    };
    let parse_date = |value: &String| -> Result<chrono::NaiveDateTime> {
        Ok(chrono::DateTime::parse_from_rfc3339(value)
            .with_context(|| format!("Invalid date value {value}"))?
            .naive_utc())
    };
    let parse_photo = |value: &String| -> Result<JpegPhoto> {
        JpegPhoto::try_from(value.as_str()).context("Provided image is not a valid JPEG")
    };
    let parse_bool = |value: &String| -> Result<bool> {
        value
            .parse::<bool>()
            .with_context(|| format!("Invalid boolean value {value}"))
    };
    Ok(match (typ, is_list) {
        (AttributeType::String, false) => value[0].clone().into(),
        (AttributeType::String, true) => value.to_vec().into(),
        (AttributeType::Integer, false) => (parse_int(&value[0])?).into(),
        (AttributeType::Integer, true) => {
            (value.iter().map(parse_int).collect::<Result<Vec<_>>>()?).into()
        }
        (AttributeType::DateTime, false) => (parse_date(&value[0])?).into(),
        (AttributeType::DateTime, true) => {
            (value.iter().map(parse_date).collect::<Result<Vec<_>>>()?).into()
        }
        (AttributeType::JpegPhoto, false) => (parse_photo(&value[0])?).into(),
        (AttributeType::JpegPhoto, true) => {
            (value.iter().map(parse_photo).collect::<Result<Vec<_>>>()?).into()
        }
        (AttributeType::Boolean, false) => (parse_bool(&value[0])?).into(),
        (AttributeType::Boolean, true) => {
            (value.iter().map(parse_bool).collect::<Result<Vec<_>>>()?).into()
        }
    })
}
