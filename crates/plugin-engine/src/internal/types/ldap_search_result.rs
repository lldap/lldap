use crate::{
    api::arguments::ldap_search_result::SearchResult,
    internal::types::{group::LuaGroup, user::LuaUserAndGroups},
};
use ldap3_proto::proto::LdapOp;
use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Table, Value};

#[derive(Clone, Debug)]
pub enum LuaSearchResult {
    UsersAndGroups(Vec<LuaUserAndGroups>, Vec<LuaGroup>),
    Ldap(Vec<LdapOp>),
    Empty,
}

impl From<SearchResult> for LuaSearchResult {
    fn from(value: SearchResult) -> Self {
        match value {
            SearchResult::UsersAndGroups(u, g) => LuaSearchResult::UsersAndGroups(
                u.into_iter().map(LuaUserAndGroups::from).collect(),
                g.into_iter().map(LuaGroup::from).collect(),
            ),
            SearchResult::Ldap(ldap_op) => LuaSearchResult::Ldap(ldap_op),
            SearchResult::Empty => LuaSearchResult::Empty,
        }
    }
}

impl Into<SearchResult> for LuaSearchResult {
    fn into(self) -> SearchResult {
        match self {
            LuaSearchResult::UsersAndGroups(u, g) => SearchResult::UsersAndGroups(
                u.into_iter().map(LuaUserAndGroups::into).collect(),
                g.into_iter().map(LuaGroup::into).collect(),
            ),
            LuaSearchResult::Ldap(ldap_op) => SearchResult::Ldap(ldap_op),
            LuaSearchResult::Empty => SearchResult::Empty,
        }
    }
}

impl IntoLua for LuaSearchResult {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        match self {
            LuaSearchResult::UsersAndGroups(u, g) => {
                let ug = lua.create_table()?;
                ug.set("users", u)?;
                ug.set("groups", g)?;
                t.set("users_and_groups", Value::Table(ug))?;
            }
            LuaSearchResult::Ldap(vec) => {
                t.set("ldap", lua.to_value(&vec)?)?;
            }
            LuaSearchResult::Empty => {
                t.set("empty", Value::Table(lua.create_table()?))?;
            }
        }
        Ok(Value::Table(t))
    }
}

impl FromLua for LuaSearchResult {
    fn from_lua(value: Value, lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => {
                if t.contains_key("empty")? {
                    Ok(LuaSearchResult::Empty)
                } else if t.contains_key("ldap")? {
                    Ok(LuaSearchResult::Ldap(lua.from_value(t.get("ldap")?)?))
                } else if t.contains_key("users_and_groups")? {
                    let ug: Table = t.get("users_and_groups")?;
                    Ok(LuaSearchResult::UsersAndGroups(
                        ug.get("users")?,
                        ug.get("groups")?,
                    ))
                } else {
                    Err(Error::FromLuaConversionError {
                        from: "{unknown}",
                        to: "LuaSearchResult".to_string(),
                        message: Some("Lua table expected".to_string()),
                    })
                }
            }
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "LuaSearchResult".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
