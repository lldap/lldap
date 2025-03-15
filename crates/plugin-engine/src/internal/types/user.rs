use crate::internal::types::{datetime::LuaDateTime, group::LuaGroupDetails};
use lldap_domain::types::{Email, User, UserAndGroups, UserId, Uuid};
use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};

use super::attribute_map::AttributeMapArgument;

#[derive(Clone, Debug)]
pub struct LuaUser {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub creation_date: LuaDateTime,
    pub uuid: String,
    pub attributes: AttributeMapArgument,
}

impl From<User> for LuaUser {
    fn from(user: User) -> Self {
        LuaUser {
            user_id: user.user_id.into_string(),
            email: user.email.into_string(),
            display_name: user.display_name,
            creation_date: user.creation_date.into(),
            uuid: user.uuid.into_string(),
            attributes: AttributeMapArgument(user.attributes),
        }
    }
}

impl Into<User> for LuaUser {
    fn into(self) -> User {
        User {
            user_id: UserId::from(self.user_id),
            email: Email::from(self.email),
            display_name: self.display_name,
            creation_date: self.creation_date.datetime,
            uuid: Uuid::try_from(self.uuid.as_str()).unwrap(),
            attributes: self.attributes.0,
        }
    }
}

impl IntoLua for LuaUser {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("user_id", lua.to_value(&self.user_id)?)?;
        t.set("email", lua.to_value(&self.email)?)?;
        t.set("display_name", lua.to_value(&self.display_name)?)?;
        t.set("creation_date", self.creation_date)?;
        t.set("uuid", lua.to_value(&self.uuid)?)?;
        t.set("attributes", self.attributes)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for LuaUser {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(LuaUser {
                user_id: t.get("user_id")?,
                email: t.get("email")?,
                display_name: t.get("display_name")?,
                creation_date: t.get("creation_date")?,
                uuid: t.get("uuid")?,
                attributes: t.get("attributes")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "LuaUser".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LuaUserAndGroups {
    pub user: LuaUser,
    pub groups: Option<Vec<LuaGroupDetails>>,
}

impl IntoLua for LuaUserAndGroups {
    fn into_lua(self, lua: &mlua::Lua) -> mlua::Result<mlua::Value> {
        let t = lua.create_table()?;
        let groups = self.groups.unwrap_or_default();
        t.set("user", self.user)?;
        t.set("groups", groups)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for LuaUserAndGroups {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => {
                let groups: Vec<LuaGroupDetails> = t.get("groups")?;
                Ok(LuaUserAndGroups {
                    user: t.get("user")?,
                    groups: if groups.is_empty() {
                        None
                    } else {
                        Some(groups)
                    },
                })
            }
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "LuaUserAndGroups".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LuaUserAndGroupsVec {
    pub user_and_groups: Vec<LuaUserAndGroups>,
}

impl From<UserAndGroups> for LuaUserAndGroups {
    fn from(ug: UserAndGroups) -> Self {
        LuaUserAndGroups {
            user: ug.user.into(),
            groups: match ug.groups {
                Some(groups) => Some(groups.into_iter().map(|g| g.into()).collect()),
                None => None,
            },
        }
    }
}

impl Into<UserAndGroups> for LuaUserAndGroups {
    fn into(self) -> UserAndGroups {
        UserAndGroups {
            user: self.user.into(),
            groups: match self.groups {
                Some(groups) => Some(groups.into_iter().map(LuaGroupDetails::into).collect()),
                None => None,
            },
        }
    }
}

impl From<Vec<UserAndGroups>> for LuaUserAndGroupsVec {
    fn from(v: Vec<UserAndGroups>) -> Self {
        LuaUserAndGroupsVec {
            user_and_groups: v.into_iter().map(|ug| ug.into()).collect(),
        }
    }
}
