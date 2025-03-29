use mlua::{Result as LuaResult, Table};

use lldap_domain::{
    requests::UpdateGroupRequest,
    types::{AttributeName, GroupId, GroupName},
};

use crate::internal::types::attribute_map::AttributeMapArgument;

use super::utils::{get_opt_arg, get_opt_attrmap, get_opt_vec};

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct UpdateGroupParams {
    pub group_id: i32,
    pub display_name: Option<String>,
    pub delete_attributes: Vec<String>,
    pub insert_attributes: AttributeMapArgument,
}

impl UpdateGroupParams {
    pub fn from(args: &Table) -> LuaResult<Self> {
        Ok(UpdateGroupParams {
            group_id: args.get("group_id")?,
            display_name: get_opt_arg("display_name", args)?,
            delete_attributes: get_opt_vec("delete_attributes", args)?,
            insert_attributes: get_opt_attrmap("insert_attributes", args)?,
        })
    }
}

impl Into<UpdateGroupRequest> for UpdateGroupParams {
    fn into(self) -> UpdateGroupRequest {
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
