use crate::{
    api::{backend::BackendAPI, types::PluginContext},
    internal::{
        context::plugin_context::LuaPluginContext, types::plugins::Callback,
        types::result::MyLuaResult,
    },
};
use lldap_key_value_store::api::store::KeyValueStore;
use lldap_plugin_kv_store::store::ScopeAndKey;
use mlua::{FromLua, FromLuaMulti, IntoLua, Lua};

use tracing::{debug, debug_span, error, Instrument};

use super::types::plugins::Plugin;

// Executes a list of "mutating" event handlers.
//
// This basicly performs a fold over the list of registered event handlers from all plugins,
// over the args object. Each plugin event handler can mutate the structure as required, and
// the result will be carried to the next handler, and so on. The result of this is returned
// to the caller.
pub async fn exec_mutation_handler<
    A: BackendAPI,
    T: IntoLua + FromLua + std::fmt::Debug + Clone,
    KVStore: KeyValueStore<ScopeAndKey> + 'static,
>(
    context: PluginContext<A>,
    kvstore: KVStore,
    lua: &'static Lua,
    handlers: &Vec<Callback>,
    args: T,
) -> Result<T, String> {
    if handlers.is_empty() {
        Ok(args)
    } else {
        let mut a = args.clone();
        for cb in handlers.iter() {
            // Obtain reference to plugin being executed
            let plugin_ref: &Plugin = cb.plugin.as_ref();
            // Prepare actual context for plugin
            let ctx = LuaPluginContext {
                api: context.api,
                configuration: plugin_ref.configuration.clone(),
                credentials: context.credentials.clone(),
                kvstore: kvstore.clone(),
                kvscope: plugin_ref.kvstore_scope.clone(),
                lua,
            };
            let plugin_name = plugin_ref.name.clone();
            let span = debug_span!("[Lua Plugin Handler]");
            span.in_scope(|| {
                debug!(?plugin_name);
            });
            let exec_res = cb
                .callback
                .call_async((ctx.clone(), a.clone()))
                .instrument(span)
                .await
                .map_err(|e| e.to_string());
            match exec_res {
                Ok(res) => {
                    let decode_res: Result<MyLuaResult<T>, String> =
                        FromLuaMulti::from_lua_multi(res, lua).map_err(|e| e.to_string());
                    match decode_res {
                        Ok(plugin_res) => match plugin_res.0 {
                            Ok(v) => {
                                debug!("Result from Lua: {:#?}", v);
                                a = v;
                            }
                            Err(_e) => {
                                error!("Plugin reported failed execution. Skipping.");
                            }
                        },
                        Err(e) => {
                            error!("Failed to decode result from plugin. Skipping: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to execute plugin handler. Skipping: {}", e);
                }
            }
        }
        Ok(a)
    }
}

// Execute a list of non-mutating event handlers.
//
// A list of event handlers are iteratively called with the same args object. Any
// result returned is discarded, so they any mutations they perform on the arguments
// does not have any effect.
pub async fn exec_notification_handler<
    A: BackendAPI,
    T: IntoLua + std::fmt::Debug + Clone,
    KVStore: KeyValueStore<ScopeAndKey> + 'static,
>(
    context: PluginContext<A>,
    kvstore: KVStore,
    lua: &'static Lua,
    handlers: &Vec<Callback>,
    args: T,
) -> Result<(), String> {
    if !handlers.is_empty() {
        for cb in handlers.iter() {
            // Obtain reference to plugin being executed
            let plugin_ref: &Plugin = cb.plugin.as_ref();
            // Prepare actual context for plugin
            let ctx = LuaPluginContext {
                api: context.api,
                configuration: plugin_ref.configuration.clone(),
                credentials: context.credentials.clone(),
                kvstore: kvstore.clone(),
                kvscope: plugin_ref.kvstore_scope.clone(),
                lua,
            };
            let plugin_name = plugin_ref.name.clone();
            let span = debug_span!("[Lua Plugin Handler]");
            span.in_scope(|| {
                debug!(?plugin_name);
            });
            let exec_res = cb
                .callback
                .call_async::<()>((ctx.clone(), args.clone()))
                .instrument(span.clone())
                .await
                .map_err(|e| e.to_string());
            match exec_res {
                Ok(_) => span.in_scope(|| debug!("Plugin handler completed succesfully.")),
                Err(e) => {
                    error!("Failed to execute plugin. Skipping: {}", e);
                }
            }
        }
    }
    Ok(())
}
