use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::{
    requests::UpdateUserRequest,
    types::{AttributeName, Email, UserId},
};

use crate::internal::types::attribute_map::AttributeMapArgument;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct UpdateUserArguments {
    pub user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub delete_attributes: Vec<String>,
    pub insert_attributes: AttributeMapArgument,
}

impl UpdateUserArguments {
    pub fn from(request: UpdateUserRequest) -> Self {
        UpdateUserArguments {
            user_id: request.user_id.clone().into_string(),
            email: request.email.map(Email::into_string),
            display_name: request.display_name,
            delete_attributes: request
                .delete_attributes
                .into_iter()
                .map(AttributeName::into_string)
                .collect(),
            insert_attributes: AttributeMapArgument(request.insert_attributes),
        }
    }

    pub fn into_request(self) -> UpdateUserRequest {
        UpdateUserRequest {
            user_id: UserId::from(self.user_id),
            email: self.email.map(Email::from),
            display_name: self.display_name,
            delete_attributes: self
                .delete_attributes
                .into_iter()
                .map(AttributeName::from)
                .collect(),
            insert_attributes: self.insert_attributes.0,
        }
    }
}

impl IntoLua for UpdateUserArguments {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("user_id", lua.to_value(&self.user_id)?)?;
        t.set("email", lua.to_value(&self.email)?)?;
        t.set(
            "display_name",
            match self.display_name {
                Some(n) => lua.to_value(&n)?,
                None => Value::Nil,
            },
        )?;
        t.set("delete_attributes", self.delete_attributes)?;
        t.set("insert_attributes", self.insert_attributes)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for UpdateUserArguments {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(UpdateUserArguments {
                user_id: t.get("user_id")?,
                email: t.get("email")?,
                display_name: t.get("display_name")?,
                delete_attributes: t.get("delete_attributes")?,
                insert_attributes: t.get("insert_attributes")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "UpdateUserArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
