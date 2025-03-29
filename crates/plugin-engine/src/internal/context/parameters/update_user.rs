use mlua::{Result as LuaResult, Table};

use lldap_domain::{
    requests::UpdateUserRequest,
    types::{AttributeName, Email, UserId},
};

use crate::internal::types::attribute_map::AttributeMapArgument;

use super::utils::{get_opt_arg, get_opt_attrmap, get_opt_vec};

#[derive(Debug, Clone)]
pub struct UpdateUserParams {
    pub user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub delete_attributes: Vec<String>,
    pub insert_attributes: AttributeMapArgument,
}

impl UpdateUserParams {
    pub fn from(args: &Table) -> LuaResult<Self> {
        Ok(UpdateUserParams {
            user_id: args.get("user_id")?,
            email: get_opt_arg("email", args)?,
            display_name: get_opt_arg("display_name", args)?,
            delete_attributes: get_opt_vec("delete_attributes", args)?,
            insert_attributes: get_opt_attrmap("insert_attributes", args)?,
        })
    }
}

impl Into<UpdateUserRequest> for UpdateUserParams {
    fn into(self) -> UpdateUserRequest {
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
