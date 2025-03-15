use chrono::{DateTime, NaiveDateTime, TimeZone};
use mlua::{Error, FromLua, IntoLua, LuaSerdeExt, Result as LuaResult};

#[derive(Clone, Debug)]
pub struct LuaDateTime {
    pub datetime: NaiveDateTime,
}

impl From<NaiveDateTime> for LuaDateTime {
    fn from(value: NaiveDateTime) -> Self {
        LuaDateTime { datetime: value }
    }
}

pub fn datetime_to_rfc3339(dt: &NaiveDateTime) -> String {
    let dtutc = chrono::Utc.from_utc_datetime(&dt);
    dtutc.to_rfc3339()
}

pub fn datetime_from_rfc3389(s: String) -> LuaResult<NaiveDateTime> {
    match DateTime::parse_from_rfc3339(s.as_str()) {
        Ok(v) => Ok(v.naive_utc()),
        Err(_) => Err(Error::FromLuaConversionError {
            from: "{datetime-rfc3339}",
            to: "DateTime".to_string(),
            message: Some("Invalid rfc3339 datetime format string".to_string()),
        }),
    }
}

impl IntoLua for LuaDateTime {
    fn into_lua(self, lua: &mlua::Lua) -> mlua::Result<mlua::Value> {
        lua.to_value(&datetime_to_rfc3339(&self.datetime))
    }
}

impl FromLua for LuaDateTime {
    fn from_lua(value: mlua::Value, lua: &mlua::Lua) -> LuaResult<Self> {
        let s: String = lua.from_value(value)?;
        let dt = datetime_from_rfc3389(s)?;
        Ok(LuaDateTime { datetime: dt })
    }
}
