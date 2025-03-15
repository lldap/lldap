use ldap3_proto::proto::LdapSearchRequest;
use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Value};

use crate::{
    api::arguments::ldap_search_result::SearchResult,
    internal::types::ldap_search_result::LuaSearchResult,
};

#[derive(Clone, Debug)]
pub struct SearchResultArguments {
    pub search_result: LuaSearchResult,
    pub search_request: LdapSearchRequest,
}

impl SearchResultArguments {
    pub fn new(result: SearchResult, request: LdapSearchRequest) -> Self {
        Self {
            search_result: LuaSearchResult::from(result),
            search_request: request,
        }
    }
}

impl IntoLua for SearchResultArguments {
    fn into_lua(self, lua: &Lua) -> mlua::Result<Value> {
        let t = lua.create_table()?;
        t.set("search_result", self.search_result)?;
        t.set("search_request", lua.to_value(&self.search_request)?)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for SearchResultArguments {
    fn from_lua(value: Value, lua: &Lua) -> mlua::Result<Self> {
        match value {
            Value::Table(t) => Ok(SearchResultArguments {
                search_result: t.get("search_result")?,
                search_request: lua.from_value(t.get("search_request")?)?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "SearchResultArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
