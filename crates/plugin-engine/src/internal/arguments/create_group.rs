use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::requests::CreateGroupRequest;

use crate::internal::types::attribute_map::AttributeMapArgument;

#[derive(Clone, Serialize, Deserialize, Default, Debug, tealr::ToTypename)]
pub struct CreateGroupArguments {
    pub display_name: String,
    pub attributes: AttributeMapArgument,
}

impl CreateGroupArguments {
    pub fn from(request: CreateGroupRequest) -> Self {
        CreateGroupArguments {
            display_name: request.display_name.into_string(),
            attributes: AttributeMapArgument(request.attributes),
        }
    }

    pub fn into_request(self) -> CreateGroupRequest {
        CreateGroupRequest {
            display_name: self.display_name.into(),
            attributes: self.attributes.0,
        }
    }
}

impl IntoLua for CreateGroupArguments {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("display_name", lua.to_value(&self.display_name)?)?;
        t.set("attributes", self.attributes)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for CreateGroupArguments {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(CreateGroupArguments {
                display_name: t.get("display_name")?,
                attributes: t.get("attributes")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "CreateGroupArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
