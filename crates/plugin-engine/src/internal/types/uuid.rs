use lldap_domain::types::Uuid;
use mlua::{FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LuaUuid {
    pub uuid: Uuid,
}

impl From<Uuid> for LuaUuid {
    fn from(value: Uuid) -> Self {
        LuaUuid { uuid: value }
    }
}

impl IntoLua for LuaUuid {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        lua.to_value(&self.uuid.into_string())
    }
}

impl FromLua for LuaUuid {
    fn from_lua(value: Value, lua: &Lua) -> LuaResult<Self> {
        let s: String = lua.from_value(value)?;
        match Uuid::try_from(s.as_str()) {
            Ok(uuid) => Ok(LuaUuid { uuid }),
            Err(_e) => Err(mlua::Error::FromLuaConversionError {
                from: "string",
                to: "Uuid".to_string(),
                message: Some("Unable to convert string to Uuid".to_string()),
            }),
        }
    }
}
