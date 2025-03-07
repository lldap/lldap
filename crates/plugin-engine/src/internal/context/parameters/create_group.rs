use lldap_domain::{requests::CreateGroupRequest, types::GroupName};
use mlua::{Result as LuaResult, Table};

use crate::internal::types::attribute_map::AttributeMapArgument;

use super::utils;

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct CreateGroupParams {
    pub display_name: String,
    pub attributes: AttributeMapArgument,
}
impl CreateGroupParams {
    pub fn from(args: &Table) -> LuaResult<Self> {
        Ok(CreateGroupParams {
            display_name: args.get("display_name")?,
            attributes: utils::get_opt_attrmap("attributes", args)?,
        })
    }
}

impl Into<CreateGroupRequest> for CreateGroupParams {
    fn into(self) -> CreateGroupRequest {
        CreateGroupRequest {
            display_name: GroupName::from(self.display_name),
            attributes: self.attributes.0,
        }
    }
}
