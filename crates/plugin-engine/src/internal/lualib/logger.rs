use mlua::{UserData, UserDataMethods};
use tracing::{debug, info, warn};

pub struct LuaLogger;

impl UserData for LuaLogger {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("debug", |_, _, s: String| Ok(debug!("{}", s)));
        methods.add_method("info", |_, _, s: String| Ok(info!("{}", s)));
        methods.add_method("warn", |_, _, s: String| Ok(warn!("{}", s)));
    }
}
