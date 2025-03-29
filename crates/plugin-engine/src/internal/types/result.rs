use mlua::{
    Error as LuaError, FromLua, IntoLua, IntoLuaMulti, Lua, LuaSerdeExt, Result as LuaResult,
};

pub struct MyLuaResult<T>(pub Result<T, String>);

impl<T: IntoLuaMulti> IntoLuaMulti for MyLuaResult<T> {
    fn into_lua_multi(self, lua: &Lua) -> LuaResult<mlua::MultiValue> {
        match self.0 {
            Ok(v) => v.into_lua_multi(lua),
            Err(s) => Ok(mlua::MultiValue::from_iter([
                lua.null(),
                mlua::String::wrap(s.as_bytes()).into_lua(lua)?,
            ])),
        }
    }
}

impl<T> From<anyhow::Result<T>> for MyLuaResult<T> {
    fn from(value: anyhow::Result<T>) -> Self {
        Self(value.map_err(|e| e.to_string()))
    }
}

impl<T: FromLua> mlua::FromLuaMulti for MyLuaResult<T> {
    fn from_lua_multi(values: mlua::MultiValue, lua: &Lua) -> LuaResult<Self> {
        let mut values = values.into_vec();
        if values.len() == 1 {
            Ok(MyLuaResult(Ok(FromLua::from_lua(values.remove(0), lua)?)))
        } else if values.len() == 2 {
            if values[0].is_nil() {
                Ok(MyLuaResult(Err(lua.from_value(values.remove(1))?)))
            } else {
                Err(LuaError::external("Multiple values not supported"))
            }
        } else if values.is_empty() {
            unreachable!()
        } else {
            Err(LuaError::external("Too many values"))
        }
    }
}
