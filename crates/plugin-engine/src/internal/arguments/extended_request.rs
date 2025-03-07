use ldap3_proto::proto::{LdapExtendedRequest, LdapOp};
use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Value};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtendedRequestArguments {
    pub extended_result: Vec<LdapOp>,
    pub extended_request: LdapExtendedRequest,
}

impl ExtendedRequestArguments {
    pub fn new(result: Vec<LdapOp>, request: LdapExtendedRequest) -> Self {
        Self {
            extended_result: result,
            extended_request: request,
        }
    }
}

impl IntoLua for ExtendedRequestArguments {
    fn into_lua(self, lua: &Lua) -> mlua::Result<Value> {
        let t = lua.create_table()?;
        t.set("extended_result", lua.to_value(&self.extended_result)?)?;
        t.set("extended_request", lua.to_value(&self.extended_request)?)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for ExtendedRequestArguments {
    fn from_lua(value: Value, lua: &Lua) -> mlua::Result<Self> {
        match value {
            Value::Table(t) => Ok(ExtendedRequestArguments {
                extended_result: lua.from_value(t.get("extended_result")?)?,
                extended_request: lua.from_value(t.get("extended_request")?)?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "ExtendedRequestArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
