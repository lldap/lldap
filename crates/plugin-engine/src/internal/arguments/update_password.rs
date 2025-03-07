use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::types::UserId;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct UpdatePasswordArguments {
    pub user_id: String,
    pub password: String,
}

impl UpdatePasswordArguments {
    pub fn from(user_id: UserId, password: String) -> Self {
        UpdatePasswordArguments {
            user_id: user_id.into_string(),
            password,
        }
    }
}

impl IntoLua for UpdatePasswordArguments {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("user_id", lua.to_value(&self.user_id)?)?;
        t.set("password", lua.to_value(&self.password)?)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for UpdatePasswordArguments {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(UpdatePasswordArguments {
                user_id: t.get("user_id")?,
                password: t.get("password")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "UpdatePasswordArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
