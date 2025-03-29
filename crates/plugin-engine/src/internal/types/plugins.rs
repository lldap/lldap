use lldap_plugin_kv_store::store::PluginKVScope;
use mlua::{Function, Lua};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Debug)]
pub struct PluginRegistry {
    pub lua: &'static Lua,
    pub plugins: Vec<Arc<Plugin>>,
    pub init: Vec<Callback>,
    pub on_create_user: Vec<Callback>,
    pub on_created_user: Vec<Callback>,
    pub on_update_user: Vec<Callback>,
    pub on_updated_user: Vec<Callback>,
    pub on_delete_user: Vec<Callback>,
    pub on_deleted_user: Vec<Callback>,
    pub on_create_group: Vec<Callback>,
    pub on_created_group: Vec<Callback>,
    pub on_update_group: Vec<Callback>,
    pub on_updated_group: Vec<Callback>,
    pub on_delete_group: Vec<Callback>,
    pub on_deleted_group: Vec<Callback>,
    pub on_added_user_to_group: Vec<Callback>,
    pub on_removed_user_from_group: Vec<Callback>,
    pub on_ldap_password_update: Vec<Callback>,
    pub on_ldap_search_result: Vec<Callback>,
    pub on_ldap_root_dse: Vec<Callback>,
    pub on_ldap_bind: Vec<Callback>,
    pub on_ldap_unbind: Vec<Callback>,
    pub on_ldap_modify: Vec<Callback>,
    pub on_ldap_extended_request: Vec<Callback>,
}

#[derive(Clone, Debug)]
pub struct Plugin {
    pub name: String,
    pub version: String,
    pub author: String,
    pub configuration: BTreeMap<String, String>,
    pub kvstore_scope: PluginKVScope,
}

#[derive(Clone, Debug)]
pub struct Callback {
    pub plugin: Arc<Plugin>,
    pub priority: u8,
    pub callback: Function,
}
