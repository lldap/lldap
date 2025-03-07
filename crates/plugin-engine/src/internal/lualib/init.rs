use mlua::{Lua, Value};

use super::{
    encoding::LuaEncodingLib, hashing::LuaHashingLib, logger::LuaLogger, strings::LuaStringsLib,
    tables::LuaTablesLib,
};

// TODO: return and propagate a Result type
pub fn new_lua_environment() -> &'static Lua {
    let lua = Box::leak(Box::new(Lua::new()));

    let lldap_lib = lua.create_table().unwrap();
    let _ = lldap_lib.set("encoding", LuaEncodingLib {});
    let _ = lldap_lib.set("hashing", LuaHashingLib {});
    let _ = lldap_lib.set("log", LuaLogger {});
    let _ = lldap_lib.set("strings", LuaStringsLib {});
    let _ = lldap_lib.set("tables", LuaTablesLib {});

    let globals = lua.globals();
    let _ = globals.set("lldap", Value::Table(lldap_lib));

    lua
}
