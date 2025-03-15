use ldap3_proto::LdapSearchResultEntry;
use mlua::{FromLua, IntoLua, Lua, LuaSerdeExt, Value};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LdapSearchResultEntryArguments {
    pub search_result_entry: LdapSearchResultEntry,
}

impl LdapSearchResultEntryArguments {
    pub fn new(entry: LdapSearchResultEntry) -> Self {
        Self {
            search_result_entry: entry,
        }
    }
}

impl IntoLua for LdapSearchResultEntryArguments {
    fn into_lua(self, lua: &Lua) -> mlua::Result<Value> {
        lua.to_value(&self)
    }
}

impl FromLua for LdapSearchResultEntryArguments {
    fn from_lua(value: Value, lua: &Lua) -> mlua::Result<Self> {
        lua.from_value(value)
    }
}
