use super::utils::get_opt_arg;
use mlua::{Result as LuaResult, Table};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ListUsersLdapFilterParam {
    pub get_groups: bool,
    pub ldap_filter: Option<String>,
}

impl ListUsersLdapFilterParam {
    pub fn from(args: &Table) -> LuaResult<Self> {
        Ok(ListUsersLdapFilterParam {
            get_groups: get_opt_arg::<bool>("get_groups", &args)?.unwrap_or(false),
            ldap_filter: get_opt_arg("filter", &args)?,
        })
    }
}
