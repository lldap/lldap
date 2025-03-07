use lldap_domain::{
    requests::CreateUserRequest,
    types::{Email, UserId},
};
use mlua::{Result as LuaResult, Table};

use crate::internal::types::attribute_map::AttributeMapArgument;

use super::utils;

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct CreateUserParams {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub attributes: AttributeMapArgument,
}
impl CreateUserParams {
    pub fn from(args: &Table) -> LuaResult<Self> {
        Ok(CreateUserParams {
            user_id: args.get("user_id")?,
            email: args.get("email")?,
            display_name: args.get("display_name")?,
            attributes: utils::get_opt_attrmap("attributes", args)?,
        })
    }
}

impl Into<CreateUserRequest> for CreateUserParams {
    fn into(self) -> CreateUserRequest {
        CreateUserRequest {
            user_id: UserId::from(self.user_id),
            email: Email::from(self.email),
            display_name: self.display_name.into(),
            attributes: self.attributes.0,
        }
    }
}
