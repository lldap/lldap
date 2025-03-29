use ldap3_proto::LdapResultCode;
use mlua::{FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindResult {
    pub result_code: LdapResultCode,
    pub message: String,
}

impl IntoLua for BindResult {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        lua.to_value(&self)
    }
}

impl FromLua for BindResult {
    fn from_lua(value: Value, lua: &Lua) -> LuaResult<Self> {
        lua.from_value(value)
    }
}
