use lldap_key_value_store::api::store::KeyValueStore;
use lldap_plugin_kv_store::store::{PluginKVScope, ScopeAndKey};
use mlua::{Error, Lua, LuaSerdeExt, Table, UserData, UserDataMethods, Value};

use serde_json::Value as JsonValue;

use crate::internal::types::result::MyLuaResult;

pub struct LuaKeyValueStoreAPI<KVStore: KeyValueStore<ScopeAndKey> + 'static> {
    pub kvstore: KVStore,
    pub kvscope: PluginKVScope,
    pub lua: &'static Lua,
}

impl<KVStore: KeyValueStore<ScopeAndKey>> UserData for LuaKeyValueStoreAPI<KVStore> {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_async_method("store_str", |_, ctx, (key, val): (String, String)| {
            let kvstore = ctx.kvstore.clone();
            let kvscope = ctx.kvscope.clone();
            async move {
                match kvstore.store::<String>(kvscope.key(key), val).await {
                    Ok(()) => Ok(MyLuaResult(Ok(()))),
                    Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                }
            }
        });
        methods.add_async_method("store_int", |_, ctx, (key, val): (String, i64)| {
            let kvstore = ctx.kvstore.clone();
            let kvscope = ctx.kvscope.clone();
            async move {
                match kvstore.store::<i64>(kvscope.key(key), val).await {
                    Ok(()) => Ok(MyLuaResult(Ok(()))),
                    Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                }
            }
        });
        methods.add_async_method("store_table", |_, ctx, (key, val): (String, Table)| {
            let kvstore = ctx.kvstore.clone();
            let kvscope = ctx.kvscope.clone();
            let lua: &'static Lua = ctx.lua;
            async move {
                let json_value_res: Result<JsonValue, Error> =
                    lua.from_value(Value::Table(val.clone()));
                match json_value_res {
                    Ok(json_value) => match serde_json::to_string(&json_value) {
                        Ok(json_str) => {
                            match kvstore.store::<String>(kvscope.key(key), json_str).await {
                                Ok(()) => Ok(MyLuaResult(Ok(()))),
                                Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                            }
                        }
                        Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                    },
                    Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                }
            }
        });

        methods.add_async_method("fetch_str", |_, ctx, key: String| {
            let kvstore = ctx.kvstore.clone();
            let kvscope = ctx.kvscope.clone();
            async move {
                match kvstore.fetch::<String>(kvscope.key(key)).await {
                    Ok(v) => Ok(MyLuaResult(Ok(v))),
                    Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                }
            }
        });
        methods.add_async_method("fetch_int", |_, ctx, key: String| {
            let kvstore = ctx.kvstore.clone();
            let kvscope = ctx.kvscope.clone();
            async move {
                match kvstore.fetch::<i64>(kvscope.key(key)).await {
                    Ok(v) => Ok(MyLuaResult(Ok(v))),
                    Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                }
            }
        });
        methods.add_async_method("fetch_table", |_, ctx, key: String| {
            let kvstore = ctx.kvstore.clone();
            let kvscope = ctx.kvscope.clone();
            let lua: &'static Lua = ctx.lua;
            async move {
                match kvstore.fetch::<String>(kvscope.key(key)).await {
                    Ok(v) => match v {
                        Some(s) => match serde_json::from_str::<JsonValue>(s.as_str()) {
                            Ok(json_value) => Ok(MyLuaResult(
                                lua.to_value(&json_value)
                                    .map(|v| Some(v))
                                    .map_err(|e| e.to_string()),
                            )),
                            Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                        },
                        None => Ok(MyLuaResult(Ok(None))),
                    },
                    Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                }
            }
        });
        methods.add_async_method("remove", |_, ctx, key: String| {
            let kvstore = ctx.kvstore.clone();
            let kvscope = ctx.kvscope.clone();
            async move {
                match kvstore.remove(kvscope.key(key)).await {
                    Ok(()) => Ok(MyLuaResult(Ok(()))),
                    Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                }
            }
        });
        methods.add_async_method(
            "fetch_and_increment",
            |_, ctx, (key, default_val): (String, i64)| {
                let kvstore = ctx.kvstore.clone();
                let kvscope = ctx.kvscope.clone();
                async move {
                    match kvstore
                        .fetch_and_increment(kvscope.key(key), default_val)
                        .await
                    {
                        Ok(v) => Ok(MyLuaResult(Ok(v))),
                        Err(e) => Ok(MyLuaResult(Err(e.to_string()))),
                    }
                }
            },
        );
    }
}
