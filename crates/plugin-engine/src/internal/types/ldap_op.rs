use ldap3_proto::{
    proto::{LdapBindRequest, LdapOp, LdapResult},
    LdapResultCode,
};
use mlua::{FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Table, Value};

#[derive(Clone, Debug)]
pub struct LuaLdapOp {
    pub ldap_op: LdapOp,
}
/*
fn ldap_key_val(lua: &Lua, name: &str, v: Value) -> LuaResult<Table> {
    let t = lua.create_table()?;
    t.set(name, v)?;
    Ok(t)
}
*/

impl IntoLua for LuaLdapOp {
    fn into_lua(self, lua: &Lua) -> LuaResult<mlua::Value> {
        lua.to_value(&self.ldap_op)
        /*
        Ok(Value::Table(match self.ldap_op {
            LdapOp::BindRequest(ldap_bind_request) => ldap_key_val(
                lua,
                "bindRequest",
                Value::Table(_bind_request(lua, &ldap_bind_request)?),
            )?,
            LdapOp::BindResponse(ldap_bind_response) => ldap_key_val(lua, "bindResponse")?,
            LdapOp::UnbindRequest => todo!(),
            LdapOp::SearchRequest(ldap_search_request) => todo!(),
            LdapOp::SearchResultEntry(ldap_search_result_entry) => todo!(),
            LdapOp::SearchResultDone(ldap_result) => todo!(),
            LdapOp::SearchResultReference(ldap_search_result_reference) => todo!(),
            LdapOp::ModifyRequest(ldap_modify_request) => todo!(),
            LdapOp::ModifyResponse(ldap_result) => todo!(),
            LdapOp::AddRequest(ldap_add_request) => todo!(),
            LdapOp::AddResponse(ldap_result) => todo!(),
            LdapOp::DelRequest(_) => todo!(),
            LdapOp::DelResponse(ldap_result) => todo!(),
            LdapOp::ModifyDNRequest(ldap_modify_dnrequest) => todo!(),
            LdapOp::ModifyDNResponse(ldap_result) => todo!(),
            LdapOp::CompareRequest(ldap_compare_request) => todo!(),
            LdapOp::CompareResult(ldap_result) => todo!(),
            LdapOp::AbandonRequest(_) => todo!(),
            LdapOp::ExtendedRequest(ldap_extended_request) => todo!(),
            LdapOp::ExtendedResponse(ldap_extended_response) => todo!(),
            LdapOp::IntermediateResponse(ldap_intermediate_response) => todo!(),
        }))
        */
    }
}

impl FromLua for LuaLdapOp {
    fn from_lua(value: Value, lua: &Lua) -> LuaResult<Self> {
        let ldap_op: LdapOp = lua.from_value(value)?;
        Ok(LuaLdapOp { ldap_op })
    }
}

/*
fn _ldap_result_code(lua: &Lua, result_code: &LdapResultCode) -> LuaResult<Value> {
    lua.to_value(result_code)
}
fn _ldap_result(lua: &Lua, result: &LdapResult) -> LuaResult<Value> {
    result.
}

fn _bind_request(lua: &Lua, bind_request: &LdapBindRequest) -> LuaResult<Table> {
    let t = lua.create_table()?;
    t.set(bind_request.dn.as_str(), lua.to_value(&bind_request.dn)?)?;
    t.set(
        "credentials",
        Value::Table(match &bind_request.cred {
            ldap3_proto::proto::LdapBindCred::Simple(s) => {
                ldap_key_val(lua, "simple", lua.to_value(&s)?)?
            }
            ldap3_proto::proto::LdapBindCred::SASL(sasl_credentials) => {
                let creds = lua.create_table()?;
                creds.set("mechanism", lua.to_value(&sasl_credentials.mechanism)?)?;
                creds.set("credentials", lua.to_value(&sasl_credentials.credentials)?)?;
                ldap_key_val(
                    lua,
                    "sasl",
                    Value::Table(ldap_key_val(lua, "credentials", Value::Table(creds))?),
                )?
            }
        }),
    )?;
    Ok(t)
}
*/
