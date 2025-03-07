use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::types::GroupId;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct DeleteGroupArguments {
    pub group_id: i32,
}

impl DeleteGroupArguments {
    pub fn from(group_id: GroupId) -> Self {
        DeleteGroupArguments {
            group_id: group_id.0,
        }
    }
    pub fn into_group_id(self) -> GroupId {
        GroupId(self.group_id)
    }
}

impl IntoLua for DeleteGroupArguments {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("group_id", lua.to_value(&self.group_id)?)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for DeleteGroupArguments {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(DeleteGroupArguments {
                group_id: t.get("group_id")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "DeleteGroupArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
