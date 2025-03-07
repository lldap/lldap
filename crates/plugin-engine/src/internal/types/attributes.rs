use chrono::NaiveDateTime;
use lldap_domain::types::{Attribute, AttributeName, AttributeValue, Cardinality, JpegPhoto};
use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Table, Value};
use serde::{Deserialize, Serialize};

use crate::internal::types::datetime::{datetime_from_rfc3389, datetime_to_rfc3339};

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LuaAttribute {
    pub name: AttributeName,
    pub value: LuaAttributeValue,
}

impl From<Attribute> for LuaAttribute {
    fn from(value: Attribute) -> Self {
        LuaAttribute {
            name: value.name,
            value: value.value.into(),
        }
    }
}

impl Into<Attribute> for LuaAttribute {
    fn into(self) -> Attribute {
        Attribute {
            name: self.name,
            value: self.value.value,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct LuaAttributeValue {
    pub value: AttributeValue,
}

impl From<AttributeValue> for LuaAttributeValue {
    fn from(value: AttributeValue) -> Self {
        LuaAttributeValue { value }
    }
}

impl IntoLua for LuaAttributeValue {
    fn into_lua(self, lua: &Lua) -> mlua::Result<Value> {
        let t = lua.create_table()?;
        match self.value {
            AttributeValue::String(Cardinality::Singleton(s)) => {
                t.set("string", lua.to_value(&s)?)?;
            }
            AttributeValue::String(Cardinality::Unbounded(l)) => {
                t.set("strings", lua.to_value(&l)?)?;
            }
            AttributeValue::Integer(Cardinality::Singleton(i)) => {
                t.set("int", lua.to_value(&i)?)?;
            }
            AttributeValue::Integer(Cardinality::Unbounded(l)) => {
                t.set("ints", lua.to_value(&l)?)?;
            }
            AttributeValue::DateTime(Cardinality::Singleton(dt)) => {
                t.set("datetime", lua.to_value(&datetime_to_rfc3339(&dt))?)?;
            }
            AttributeValue::DateTime(Cardinality::Unbounded(l)) => {
                t.set(
                    "datetimes",
                    lua.to_value(&l.iter().map(datetime_to_rfc3339).collect::<Vec<_>>())?,
                )?;
            }
            AttributeValue::JpegPhoto(Cardinality::Singleton(p)) => {
                t.set("jpeg_photo", lua.to_value(&p.clone().into_bytes())?)?;
            }
            AttributeValue::JpegPhoto(Cardinality::Unbounded(l)) => {
                t.set(
                    "jpeg_photos",
                    lua.to_value(
                        &l.clone()
                            .into_iter()
                            .map(JpegPhoto::into_bytes)
                            .collect::<Vec<Vec<_>>>(),
                    )?,
                )?;
            }
        }
        Ok(Value::Table(t))
    }
}

pub fn parse_attribute_value(val: Table) -> LuaResult<AttributeValue> {
    if val.contains_key("string")? {
        Ok(AttributeValue::String(Cardinality::Singleton(
            val.get("string")?,
        )))
    } else if val.contains_key("strings")? {
        Ok(AttributeValue::String(Cardinality::Unbounded(
            val.get("strings")?,
        )))
    } else if val.contains_key("int")? {
        Ok(AttributeValue::Integer(Cardinality::Singleton(
            val.get("int")?,
        )))
    } else if val.contains_key("ints")? {
        Ok(AttributeValue::Integer(Cardinality::Unbounded(
            val.get("ints")?,
        )))
    } else if val.contains_key("datetime")? {
        Ok(AttributeValue::DateTime(Cardinality::Singleton(
            datetime_from_rfc3389(val.get("datetime")?)?,
        )))
    } else if val.contains_key("datetimes")? {
        let strs: Vec<String> = val.get("datetimes")?;
        let mut dts: Vec<NaiveDateTime> = Vec::new();
        for s in strs {
            dts.push(datetime_from_rfc3389(s)?);
        }
        Ok(AttributeValue::DateTime(Cardinality::Unbounded(dts)))
    } else if val.contains_key("jpeg_photo")? {
        let v: Vec<u8> = val.get("jpeg_photo")?;
        Ok(AttributeValue::JpegPhoto(Cardinality::Singleton(
            JpegPhoto::try_from(v.as_slice()).map_err(|_| Error::FromLuaConversionError {
                from: "{jpeg_photo}",
                to: "JpegPhoto".to_string(),
                message: Some("Invalid jpeg_photo contents".to_string()),
            })?,
        )))
    } else if val.contains_key("jpeg_photos")? {
        let v: Vec<Vec<u8>> = val.get("jpeg_photos")?;
        let mut photos: Vec<JpegPhoto> = Vec::new();
        for bytes in v {
            photos.push(JpegPhoto::try_from(bytes.as_slice()).map_err(|_| {
                Error::FromLuaConversionError {
                    from: "{jpeg_photo}",
                    to: "JpegPhoto".to_string(),
                    message: Some("Invalid jpeg_photo contents".to_string()),
                }
            })?);
        }
        Ok(AttributeValue::JpegPhoto(Cardinality::Unbounded(photos)))
    } else {
        Err(Error::FromLuaConversionError {
            from: "{atribute-value}",
            to: "AttributeValue".to_string(),
            message: Some("Unknown attribute value type".to_string()),
        })
    }
}

impl FromLua for LuaAttributeValue {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(LuaAttributeValue {
                value: parse_attribute_value(t)?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "AttributeValue".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}

impl FromLua for LuaAttribute {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(LuaAttribute {
                name: t.get::<String>("name")?.into(),
                value: t.get("value")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "Attribute".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}

impl IntoLua for LuaAttribute {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("name", lua.to_value(&self.name.into_string())?)?;
        t.set("value", lua.to_value(&self.value)?)?;
        Ok(Value::Table(t))
    }
}

#[cfg(test)]
mod tests {

    /*
    use lldap_domain::types::Attribute;
    use mlua::{Lua, LuaSerdeExt};

    use super::LuaAttribute;
    #[test]
    fn test_attribute_roundtrip() {
        // Setup
        let lua: Lua = Lua::new();
        let source_attr = Attribute {
            name: "SourceAttr".into(),
            value: "string-val".into(),
        };
        let lua_source_attr: LuaAttribute = source_attr.clone().into();
        // Exercise
        let lua_val: mlua::Value = lua.to_value(&lua_source_attr).unwrap();
        assert!(lua_val.as_table().is_some());
        let lua_final_attr: LuaAttribute = lua.from_value(lua_val).unwrap();
        let final_attr: Attribute = lua_final_attr.into();
        // Verify
        assert_eq!(&source_attr, &final_attr);
    }*/
}
