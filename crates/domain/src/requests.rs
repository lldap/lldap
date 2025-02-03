use serde::{Deserialize, Serialize};

use crate::types::{
    AttributeName, AttributeType, AttributeValue, Email, GroupId, GroupName, JpegPhoto, UserId,
};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct CreateUserRequest {
    // Same fields as User, but no creation_date, and with password.
    pub user_id: UserId,
    pub email: Email,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<JpegPhoto>,
    pub attributes: Vec<AttributeValue>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct UpdateUserRequest {
    // Same fields as CreateUserRequest, but no with an extra layer of Option.
    pub user_id: UserId,
    pub email: Option<Email>,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub avatar: Option<JpegPhoto>,
    pub delete_attributes: Vec<AttributeName>,
    pub insert_attributes: Vec<AttributeValue>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone, Default)]
pub struct CreateGroupRequest {
    pub display_name: GroupName,
    pub attributes: Vec<AttributeValue>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct UpdateGroupRequest {
    pub group_id: GroupId,
    pub display_name: Option<GroupName>,
    pub delete_attributes: Vec<AttributeName>,
    pub insert_attributes: Vec<AttributeValue>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct CreateAttributeRequest {
    pub name: AttributeName,
    pub attribute_type: AttributeType,
    pub is_list: bool,
    pub is_visible: bool,
    pub is_editable: bool,
}
