use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::{
    requests::CreateUserRequest,
    types::{Email, UserId},
};

use crate::internal::types::attribute_map::AttributeMapArgument;

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct CreateUserArguments {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub attributes: AttributeMapArgument,
}

impl CreateUserArguments {
    pub fn from(request: CreateUserRequest) -> Self {
        CreateUserArguments {
            user_id: request.user_id.clone().into_string(),
            email: request.email.clone().into_string(),
            display_name: request.display_name,
            attributes: AttributeMapArgument(request.attributes),
        }
    }

    pub fn into_request(self) -> CreateUserRequest {
        CreateUserRequest {
            user_id: UserId::from(self.user_id),
            email: Email::from(self.email),
            display_name: self.display_name,
            attributes: self.attributes.0,
        }
    }
}

impl IntoLua for CreateUserArguments {
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
        t.set("attributes", self.attributes)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for CreateUserArguments {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(CreateUserArguments {
                user_id: t.get("user_id")?,
                email: t.get("email")?,
                display_name: t.get("display_name")?,
                attributes: t.get("attributes")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "CreateUserArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
