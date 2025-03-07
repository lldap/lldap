use mlua::{IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::types::{GroupId, UserId};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct UserAndGroupArguments {
    pub user_id: String,
    pub group_id: i32,
}

impl UserAndGroupArguments {
    pub fn from(user_id: UserId, group_id: GroupId) -> Self {
        UserAndGroupArguments {
            user_id: user_id.into_string(),
            group_id: group_id.0,
        }
    }
}

impl IntoLua for UserAndGroupArguments {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("user_id", lua.to_value(&self.user_id)?)?;
        t.set("group_id", lua.to_value(&self.group_id)?)?;
        Ok(Value::Table(t))
    }
}
