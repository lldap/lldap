use lldap_auth::{
    access_control::{Permission, ValidationResults},
    types::UserId,
};

use crate::{
    api::{
        handler::{PluginHandlerEvents, PluginLoader},
        types::{PluginConfig, PluginContext, PluginSource},
    },
    tests::{
        lua_scripts::make_init_script, memory_store::InMemoryKeyValueStore,
        mock_backend::MockTestServerBackendAPI,
    },
};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn plugin_config_from_file(path: &str) -> PluginConfig {
    let path = PathBuf::from(path);
    PluginConfig::from(path, Some("default".to_string()), true, BTreeMap::new()).unwrap()
}

pub fn plugin_config_from_str(source: String) -> PluginConfig {
    PluginConfig {
        plugin_source: PluginSource::ScriptSource(source),
        kvscope: Some("default".to_string()),
        allow_on_password_update: true,
        configuration: BTreeMap::new(),
    }
}

pub fn new_context_from(
    credentials: Option<ValidationResults>,
) -> PluginContext<MockTestServerBackendAPI> {
    // this will leak in tests, in actual use there will be a single instance.
    let api: &'static MockTestServerBackendAPI =
        Box::leak(Box::new(MockTestServerBackendAPI::new()));
    PluginContext::new(api, credentials)
}

pub fn new_admin_context() -> PluginContext<MockTestServerBackendAPI> {
    new_context_from(Some(ValidationResults {
        user: UserId::from("admin"),
        permission: Permission::Admin,
    }))
}

pub async fn run_plugin_init(
    kvstore: InMemoryKeyValueStore,
    init_script: &str,
) -> Result<(), String> {
    let plugins = vec![plugin_config_from_str(make_init_script(init_script))];
    let context = new_admin_context();
    let plugin_handler = PluginLoader::from(plugins, kvstore);
    plugin_handler.initialize_plugins(context).await
}
