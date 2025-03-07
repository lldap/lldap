use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::types::UserId;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct DeleteUserArguments {
    pub user_id: String,
}

impl DeleteUserArguments {
    pub fn from(user_id: UserId) -> Self {
        DeleteUserArguments {
            user_id: user_id.into_string(),
        }
    }
    pub fn into_user_id(self) -> UserId {
        UserId::from(self.user_id)
    }
}

impl IntoLua for DeleteUserArguments {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("user_id", lua.to_value(&self.user_id)?)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for DeleteUserArguments {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(DeleteUserArguments {
                user_id: t.get("user_id")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "DeleteUserArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
