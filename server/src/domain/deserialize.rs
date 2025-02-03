use anyhow::{bail, Context as AnyhowContext};
use lldap_domain::types::{AttributeType, JpegPhoto, Serialized};

pub fn deserialize_attribute_value(
    value: &[String],
    typ: AttributeType,
    is_list: bool,
) -> anyhow::Result<Serialized> {
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
        (AttributeType::String, false) => Serialized::from(&value[0]),
        (AttributeType::String, true) => Serialized::from(&value),
        (AttributeType::Integer, false) => Serialized::from(&parse_int(&value[0])?),
        (AttributeType::Integer, true) => Serialized::from(
            &value
                .iter()
                .map(parse_int)
                .collect::<anyhow::Result<Vec<_>>>()?,
        ),
        (AttributeType::DateTime, false) => Serialized::from(&parse_date(&value[0])?),
        (AttributeType::DateTime, true) => Serialized::from(
            &value
                .iter()
                .map(parse_date)
                .collect::<anyhow::Result<Vec<_>>>()?,
        ),
        (AttributeType::JpegPhoto, false) => Serialized::from(&parse_photo(&value[0])?),
        (AttributeType::JpegPhoto, true) => Serialized::from(
            &value
                .iter()
                .map(parse_photo)
                .collect::<anyhow::Result<Vec<_>>>()?,
        ),
    })
}
