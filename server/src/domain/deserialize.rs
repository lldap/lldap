use anyhow::{bail, Context as AnyhowContext};
use lldap_domain::types::{AttributeType, AttributeValue, JpegPhoto};

pub fn deserialize_attribute_value(
    value: &[String],
    typ: AttributeType,
    is_list: bool,
) -> anyhow::Result<AttributeValue> {
    if !is_list && value.len() != 1 {
        bail!("Attribute is not a list, but multiple values were provided",);
    }
    let parse_int = |value: &String| -> anyhow::Result<i64> {
        value
            .parse::<i64>()
            .with_context(|| format!("Invalid integer value {}", value))
    };
    let parse_date = |value: &String| -> anyhow::Result<chrono::NaiveDateTime> {
        Ok(chrono::DateTime::parse_from_rfc3339(value)
            .with_context(|| format!("Invalid date value {}", value))?
            .naive_utc())
    };
    let parse_photo = |value: &String| -> anyhow::Result<JpegPhoto> {
        JpegPhoto::try_from(value.as_str()).context("Provided image is not a valid JPEG")
    };
    Ok(match (typ, is_list) {
        (AttributeType::String, false) => value[0].clone().into(),
        (AttributeType::String, true) => value.into(),
        (AttributeType::Integer, false) => (parse_int(&value[0])?).into(),
        (AttributeType::Integer, true) => (value
            .iter()
            .map(parse_int)
            .collect::<anyhow::Result<Vec<_>>>()?)
        .into(),
        (AttributeType::DateTime, false) => (parse_date(&value[0])?).into(),
        (AttributeType::DateTime, true) => (value
            .iter()
            .map(parse_date)
            .collect::<anyhow::Result<Vec<_>>>()?)
        .into(),
        (AttributeType::JpegPhoto, false) => (parse_photo(&value[0])?).into(),
        (AttributeType::JpegPhoto, true) => (value
            .iter()
            .map(parse_photo)
            .collect::<anyhow::Result<Vec<_>>>()?)
        .into(),
    })
}
