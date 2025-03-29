use mlua::{Error, FromLua, IntoLua, Lua, LuaSerdeExt, Result as LuaResult, Value};
use serde::{Deserialize, Serialize};

use lldap_domain::{
    requests::UpdateGroupRequest,
    types::{AttributeName, GroupId, GroupName},
};

use crate::internal::types::attribute_map::AttributeMapArgument;

#[derive(Clone, Serialize, Deserialize, Default, Debug, tealr::ToTypename)]
pub struct UpdateGroupArguments {
    pub group_id: i32,
    pub display_name: Option<String>,
    pub delete_attributes: Vec<String>,
    pub insert_attributes: AttributeMapArgument,
}

impl UpdateGroupArguments {
    pub fn from(request: UpdateGroupRequest) -> Self {
        UpdateGroupArguments {
            group_id: request.group_id.0,
            display_name: request.display_name.map(GroupName::into_string),
            delete_attributes: request
                .delete_attributes
                .into_iter()
                .map(AttributeName::into_string)
                .collect(),
            insert_attributes: AttributeMapArgument(request.insert_attributes),
        }
    }

    pub fn into_request(self) -> UpdateGroupRequest {
        UpdateGroupRequest {
            group_id: GroupId(self.group_id),
            display_name: self.display_name.map(GroupName::from),
            delete_attributes: self
                .delete_attributes
                .into_iter()
                .map(AttributeName::from)
                .collect(),
            insert_attributes: self.insert_attributes.0,
        }
    }
}

impl IntoLua for UpdateGroupArguments {
    fn into_lua(self, lua: &Lua) -> LuaResult<Value> {
        let t = lua.create_table()?;
        t.set("group_id", lua.to_value(&self.group_id)?)?;
        t.set("display_name", lua.to_value(&self.display_name)?)?;
        t.set("delete_attributes", self.delete_attributes)?;
        t.set("insert_attributes", self.insert_attributes)?;
        Ok(Value::Table(t))
    }
}

impl FromLua for UpdateGroupArguments {
    fn from_lua(value: Value, _lua: &Lua) -> LuaResult<Self> {
        match value {
            Value::Table(t) => Ok(UpdateGroupArguments {
                group_id: t.get("group_id")?,
                display_name: t.get("display_name")?,
                delete_attributes: t.get("delete_attributes")?,
                insert_attributes: t.get("insert_attributes")?,
            }),
            _ => Err(Error::FromLuaConversionError {
                from: "{unknown}",
                to: "UpdateGroupArguments".to_string(),
                message: Some("Lua table expected".to_string()),
            }),
        }
    }
}
