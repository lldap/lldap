use crate::internal::types::datetime::LuaDateTime;
use lldap_domain::types::{Group, GroupDetails, GroupId, GroupName, UserId, Uuid};
use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};

use crate::internal::types::attribute_map::AttributeMapArgument;

#[derive(Clone, Debug)]
pub struct LuaGroupDetails {
    pub group_id: i32,
    pub display_name: String,
    pub creation_date: LuaDateTime,
    pub uuid: String,
    pub attributes: AttributeMapArgument,
}

impl From<GroupDetails> for LuaGroupDetails {
    fn from(g: GroupDetails) -> Self {
        LuaGroupDetails {
            group_id: g.group_id.0,
            display_name: g.display_name.into_string(),
            creation_date: g.creation_date.into(),
            uuid: g.uuid.into_string(),
            attributes: AttributeMapArgument(g.attributes),
        }
    }
}

impl Into<GroupDetails> for LuaGroupDetails {
    fn into(self) -> GroupDetails {
        GroupDetails {
            group_id: GroupId(self.group_id),
            display_name: GroupName::from(self.display_name),
            creation_date: self.creation_date.datetime,
            uuid: Uuid::try_from(self.uuid.as_str()).unwrap(),
            attributes: self.attributes.0,
        }
    }
}

impl IntoLua for LuaGroupDetails {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("group_id", lua.to_value(&self.group_id)?)?;
        t.set("display_name", lua.to_value(&self.display_name)?)?;
        t.set("creation_date", self.creation_date)?;
        t.set("uuid", lua.to_value(&self.uuid)?)?;
        t.set("attributes", self.attributes)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for LuaGroupDetails {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(LuaGroupDetails {
                group_id: t.get("group_id")?,
                display_name: t.get("display_name")?,
                creation_date: t.get("creation_date")?,
                uuid: t.get("uuid")?,
                attributes: t.get("attributes")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "LuaGroupDetails".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LuaGroup {
    pub group_id: i32,
    pub display_name: String,
    pub creation_date: LuaDateTime,
    pub uuid: String,
    pub users: Vec<String>,
    pub attributes: AttributeMapArgument,
}

impl From<Group> for LuaGroup {
    fn from(g: Group) -> Self {
        LuaGroup {
            group_id: g.id.0,
            display_name: g.display_name.into_string(),
            creation_date: LuaDateTime {
                datetime: g.creation_date,
            },
            uuid: g.uuid.into_string(),
            users: g.users.into_iter().map(UserId::into_string).collect(),
            attributes: AttributeMapArgument(g.attributes),
        }
    }
}

impl Into<Group> for LuaGroup {
    fn into(self) -> Group {
        Group {
            id: GroupId(self.group_id),
            display_name: GroupName::from(self.display_name),
            creation_date: self.creation_date.datetime,
            uuid: Uuid::try_from(self.uuid.as_str()).unwrap(),
            users: self.users.into_iter().map(UserId::from).collect(),
            attributes: self.attributes.0,
        }
    }
}

impl IntoLua for LuaGroup {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("group_id", lua.to_value(&self.group_id)?)?;
        t.set("display_name", lua.to_value(&self.display_name)?)?;
        t.set("creation_date", self.creation_date)?;
        t.set("uuid", lua.to_value(&self.uuid)?)?;
        t.set("users", lua.to_value(&self.users)?)?;
        t.set("attributes", self.attributes)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for LuaGroup {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(LuaGroup {
                group_id: t.get("group_id")?,
                display_name: t.get("display_name")?,
                creation_date: t.get("creation_date")?,
                uuid: t.get("uuid")?,
                users: t.get("users")?,
                attributes: t.get("attributes")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "LuaGroup".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
