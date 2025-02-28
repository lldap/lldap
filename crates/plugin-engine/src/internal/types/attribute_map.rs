use mlua::{Error, FromLua, IntoLua, Lua, Result as LuaResult, Table, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::types::Attribute;

use crate::internal::types::attributes::{parse_attribute_value, LuaAttributeValue};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeMapArgument(pub Vec<Attribute>);

impl Default for AttributeMapArgument {
    fn default() -> Self {
        AttributeMapArgument(Vec::new())
    }
}

impl IntoLua for AttributeMapArgument {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let result = lua.create_table()?;
        for attr in self.0.into_iter() {
            let v: LuaAttributeValue = attr.value.into();
            result.set(attr.name.as_str(), v)?;
        }
        Ok(Value::Table(result))
    }
}

impl FromLua for AttributeMapArgument {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => {
                let mut parsed_attributes: Vec<Attribute> = Vec::new();
                for attr in t.pairs() {
                    let (name, val_table): (String, Table) = attr?;
                    parsed_attributes.push(Attribute {
                        name: name.into(),
                        value: parse_attribute_value(val_table)?,
                    });
                }
                Ok(AttributeMapArgument(parsed_attributes))
            }
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "AttributeVecArgument".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
