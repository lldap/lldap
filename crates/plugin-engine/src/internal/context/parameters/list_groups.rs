use super::utils::get_opt_arg;
use mlua::{Result as LuaResult, Table};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ListGroupsLdapFilterParam {
    pub ldap_filter: Option<String>,
}

impl ListGroupsLdapFilterParam {
    pub fn from(args: &Table) -> LuaResult<Self> {
        Ok(ListGroupsLdapFilterParam {
            ldap_filter: get_opt_arg("filter", &args)?,
        })
    }
}
