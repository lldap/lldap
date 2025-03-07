use ldap3_proto::proto::{LdapModifyRequest, LdapOp};
use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Value};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModifyRequestArguments {
    pub modify_result: Vec<LdapOp>,
    pub modify_request: LdapModifyRequest,
}

impl ModifyRequestArguments {
    pub fn new(result: Vec<LdapOp>, request: LdapModifyRequest) -> Self {
        Self {
            modify_result: result,
            modify_request: request,
        }
    }
}

impl IntoLua for ModifyRequestArguments {
    fn into_lua(self, lua: &Lua) -> mlua::Result<Value> {
        let t = lua.create_table()?;
        t.set("modify_result", lua.to_value(&self.modify_result)?)?;
        t.set("modify_request", lua.to_value(&self.modify_request)?)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for ModifyRequestArguments {
    fn from_lua(value: Value, lua: &Lua) -> mlua::Result<Self> {
        match value {
            Value::Table(t) => Ok(ModifyRequestArguments {
                modify_result: lua.from_value(t.get("modify_result")?)?,
                modify_request: lua.from_value(t.get("modify_request")?)?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "ModifyRequestArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
