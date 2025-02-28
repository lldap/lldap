use lldap_plugin_kv_store::store::PluginKVScope;
use mlua::{Function, Result as LuaResult, Table};

use crate::{
    api::types::{PluginConfig, PluginSource},
    internal::lualib::init,
    internal::types::plugins::{Callback, Plugin, PluginRegistry},
};

use std::sync::Arc;
use tracing::{debug, warn};

fn load_plugin(plugin_config: &PluginConfig, plugins: &mut PluginRegistry) -> LuaResult<()> {
    // Execute the plugin code and obtain a registration table
    let test_module: Table = match &plugin_config.plugin_source {
        PluginSource::ScriptFile(p) => plugins.lua.load(p.clone()).eval()?,
        PluginSource::ScriptSource(s) => plugins.lua.load(s).eval()?,
    };
    // Load metadata from plugin
    let plugin_name: String = test_module.get("name")?;
    let plugin_underlying = Plugin {
        name: plugin_name.clone(),
        version: test_module.get("version")?,
        author: test_module.get("author")?,
        configuration: plugin_config.configuration.clone(),
        kvstore_scope: PluginKVScope(plugin_config.kvscope.clone().unwrap_or(plugin_name.clone())),
    };
    debug!(
        "[{}] Loading plugin '{}' version '{}'",
        &plugin_name, &plugin_name, &plugin_underlying.version
    );

    // Register the plugin meta data
    let plugin = Arc::new(plugin_underlying);
    plugins.plugins.push(Arc::clone(&plugin));

    //
    // Load initialization function from plugin
    //
    if test_module.contains_key("init")? {
        debug!("[{}] Found an initialization routine", &plugin_name);
        plugins.init.push(Callback {
            plugin: Arc::clone(&plugin),
            priority: 1,
            callback: test_module.get("init")?,
        });
    }

    //
    // Load any event handlers defined by the plugin
    //
    if test_module.contains_key("listeners")? {
        let listeners: Table = test_module.get("listeners")?;
        for listener in listeners.pairs() {
            let (_idx, table): (i32, Table) = listener?;
            if table.contains_key("event")? && table.contains_key("impl")? {
                let priority = table.get("priority").unwrap_or(50);
                let event: String = table.get("event")?;
                debug!("[{}] Loading handler for event '{}'", &plugin.name, event);
                let register_handler = |handlers: &mut Vec<Callback>, callback: Function| {
                    handlers.push(Callback {
                        plugin: Arc::clone(&plugin),
                        priority,
                        callback,
                    });
                };
                match event.as_str() {
                    "on_create_user" => {
                        register_handler(&mut plugins.on_create_user, table.get("impl")?)
                    }
                    "on_created_user" => {
                        register_handler(&mut plugins.on_created_user, table.get("impl")?)
                    }
                    "on_update_user" => {
                        register_handler(&mut plugins.on_update_user, table.get("impl")?)
                    }
                    "on_updated_user" => {
                        register_handler(&mut plugins.on_updated_user, table.get("impl")?)
                    }
                    "on_delete_user" => {
                        register_handler(&mut plugins.on_delete_user, table.get("impl")?)
                    }
                    "on_deleted_user" => {
                        register_handler(&mut plugins.on_deleted_user, table.get("impl")?)
                    }
                    "on_create_group" => {
                        register_handler(&mut plugins.on_create_group, table.get("impl")?)
                    }
                    "on_created_group" => {
                        register_handler(&mut plugins.on_created_group, table.get("impl")?)
                    }
                    "on_update_group" => {
                        register_handler(&mut plugins.on_update_group, table.get("impl")?)
                    }
                    "on_updated_group" => {
                        register_handler(&mut plugins.on_updated_group, table.get("impl")?)
                    }
                    "on_delete_group" => {
                        register_handler(&mut plugins.on_delete_group, table.get("impl")?)
                    }
                    "on_deleted_group" => {
                        register_handler(&mut plugins.on_deleted_group, table.get("impl")?)
                    }
                    "on_added_user_to_group" => {
                        register_handler(&mut plugins.on_added_user_to_group, table.get("impl")?)
                    }
                    "on_removed_user_from_group" => register_handler(
                        &mut plugins.on_removed_user_from_group,
                        table.get("impl")?,
                    ),
                    "on_ldap_password_update" => {
                        // Ensure this event handler has been explicitly permitted
                        // the the lldap config.
                        if plugin_config.allow_on_password_update {
                            register_handler(
                                &mut plugins.on_ldap_password_update,
                                table.get("impl")?,
                            )
                        }
                    }
                    "on_ldap_search_result" => {
                        register_handler(&mut plugins.on_ldap_search_result, table.get("impl")?)
                    }
                    "on_ldap_root_dse" => {
                        register_handler(&mut plugins.on_ldap_root_dse, table.get("impl")?)
                    }
                    "on_ldap_bind" => {
                        register_handler(&mut plugins.on_ldap_bind, table.get("impl")?)
                    }
                    "on_ldap_unbind" => {
                        register_handler(&mut plugins.on_ldap_unbind, table.get("impl")?)
                    }
                    "on_ldap_modify" => {
                        register_handler(&mut plugins.on_ldap_modify, table.get("impl")?)
                    }
                    "on_ldap_extended_request" => {
                        register_handler(&mut plugins.on_ldap_extended_request, table.get("impl")?)
                    }
                    _ => {
                        warn!("[{}] Unrecognized event: {}", &plugin.name, event);
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn load_plugins(plugins: Vec<PluginConfig>) -> PluginRegistry {
    let lua = init::new_lua_environment();
    let mut registry = PluginRegistry {
        lua,
        plugins: Vec::new(),
        init: Vec::new(),
        on_create_user: Vec::new(),
        on_created_user: Vec::new(),
        on_update_user: Vec::new(),
        on_updated_user: Vec::new(),
        on_delete_user: Vec::new(),
        on_deleted_user: Vec::new(),
        on_create_group: Vec::new(),
        on_created_group: Vec::new(),
        on_update_group: Vec::new(),
        on_updated_group: Vec::new(),
        on_delete_group: Vec::new(),
        on_deleted_group: Vec::new(),
        on_added_user_to_group: Vec::new(),
        on_removed_user_from_group: Vec::new(),
        on_ldap_password_update: Vec::new(),
        on_ldap_search_result: Vec::new(),
        on_ldap_root_dse: Vec::new(),
        on_ldap_bind: Vec::new(),
        on_ldap_unbind: Vec::new(),
        on_ldap_modify: Vec::new(),
        on_ldap_extended_request: Vec::new(),
    };
    plugins.iter().for_each(|p| {
        debug!("Loading plugin: {:#?} ...", p.plugin_source.to_string());
        match load_plugin(&p, &mut registry) {
            Ok(_) => {
                debug!("Loaded plugin: {:#?}", p.plugin_source.to_string());
            }
            Err(e) => {
                warn!(
                    "Failed to load plugin: {:#?}. Ignoring.",
                    p.plugin_source.to_string()
                );
                warn!("Error: {:#?}", e);
            }
        }
    });
    let sort_callbacks = |callback: &Callback| callback.priority;
    registry.on_create_user.sort_by_key(sort_callbacks);
    registry.on_created_user.sort_by_key(sort_callbacks);
    registry.on_update_user.sort_by_key(sort_callbacks);
    registry.on_updated_user.sort_by_key(sort_callbacks);
    registry.on_delete_user.sort_by_key(sort_callbacks);
    registry.on_deleted_user.sort_by_key(sort_callbacks);
    registry.on_create_group.sort_by_key(sort_callbacks);
    registry.on_created_group.sort_by_key(sort_callbacks);
    registry.on_update_group.sort_by_key(sort_callbacks);
    registry.on_updated_group.sort_by_key(sort_callbacks);
    registry.on_delete_group.sort_by_key(sort_callbacks);
    registry.on_deleted_group.sort_by_key(sort_callbacks);
    registry.on_added_user_to_group.sort_by_key(sort_callbacks);
    registry
        .on_removed_user_from_group
        .sort_by_key(sort_callbacks);
    registry.on_ldap_password_update.sort_by_key(sort_callbacks);
    registry.on_ldap_search_result.sort_by_key(sort_callbacks);
    registry.on_ldap_root_dse.sort_by_key(sort_callbacks);
    registry.on_ldap_bind.sort_by_key(sort_callbacks);
    registry.on_ldap_unbind.sort_by_key(sort_callbacks);
    registry.on_ldap_modify.sort_by_key(sort_callbacks);
    registry
        .on_ldap_extended_request
        .sort_by_key(sort_callbacks);
    registry
}
