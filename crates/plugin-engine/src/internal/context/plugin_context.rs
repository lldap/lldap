use std::collections::BTreeMap;

use lldap_auth::access_control::ValidationResults;
use lldap_key_value_store::api::store::KeyValueStore;
use lldap_plugin_kv_store::store::{PluginKVScope, ScopeAndKey};
use mlua::{Lua, LuaSerdeExt, UserData};

use crate::{api::backend::BackendAPI, internal::context::api::LuaBackendAPI};

use super::store::LuaKeyValueStoreAPI;

#[derive(Clone, Debug)]
pub struct LuaPluginContext<A: BackendAPI + 'static, KVStore: KeyValueStore<ScopeAndKey> + 'static>
{
    pub api: &'static A,
    pub lua: &'static Lua,
    pub credentials: Option<ValidationResults>,
    pub configuration: BTreeMap<String, String>,
    pub kvstore: KVStore,
    pub kvscope: PluginKVScope,
}

impl<A: BackendAPI + 'static, KVStore: KeyValueStore<ScopeAndKey>> UserData
    for LuaPluginContext<A, KVStore>
{
    fn add_fields<F: mlua::UserDataFields<Self>>(fields: &mut F) {
        fields.add_field_method_get("api", |_, ctx| {
            Ok(LuaBackendAPI {
                underlying: ctx.api,
                lua: ctx.lua,
            })
        });
        fields.add_field_method_get("configuration", |_, ctx| {
            ctx.lua.to_value(&ctx.configuration)
        });
        fields.add_field_method_get("credentials", |_, ctx| ctx.lua.to_value(&ctx.credentials));
        fields.add_field_method_get("kvstore", |_, ctx| {
            Ok(LuaKeyValueStoreAPI {
                kvstore: ctx.kvstore.clone(),
                kvscope: ctx.kvscope.clone(),
                lua: ctx.lua,
            })
        });
    }
}
