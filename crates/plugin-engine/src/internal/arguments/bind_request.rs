use ldap3_proto::proto::LdapBindRequest;
use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Value};
use serde::{Deserialize, Serialize};

use crate::api::arguments::ldap_bind_result::BindResult;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindRequestArguments {
    pub bind_result: BindResult,
    pub bind_request: LdapBindRequest,
}

impl BindRequestArguments {
    pub fn new(result: BindResult, request: LdapBindRequest) -> Self {
        Self {
            bind_result: result,
            bind_request: request,
        }
    }
}

impl IntoLua for BindRequestArguments {
    fn into_lua(self, lua: &Lua) -> mlua::Result<Value> {
        let t = lua.create_table()?;
        t.set("bind_result", self.bind_result)?;
        t.set("bind_request", lua.to_value(&self.bind_request)?)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for BindRequestArguments {
    fn from_lua(value: Value, lua: &Lua) -> mlua::Result<Self> {
        match value {
            Value::Table(t) => Ok(BindRequestArguments {
                bind_result: t.get("bind_result")?,
                bind_request: lua.from_value(t.get("bind_request")?)?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "BindRequestArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
