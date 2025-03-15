use std::collections::BTreeMap;

use lldap_domain::{
    schema::{AttributeList, AttributeSchema, Schema},
    types::AttributeType,
};
use serde::{Deserialize, Serialize};
use tealr::ToTypename;

#[derive(Clone, Debug, Serialize, Deserialize, ToTypename)]
pub struct LuaSchema {
    pub user_attributes: LuaAttributeList,
    pub group_attributes: LuaAttributeList,
    pub extra_user_object_classes: BTreeMap<String, bool>,
    pub extra_group_object_classes: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToTypename)]
pub struct LuaAttributeSchema {
    pub name: String,
    pub attribute_type: AttributeType,
    pub is_list: bool,
    pub is_visible: bool,
    pub is_editable: bool,
    pub is_hardcoded: bool,
    pub is_readonly: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToTypename)]
pub struct LuaAttributeList {
    pub attributes: BTreeMap<String, LuaAttributeSchema>,
}

impl From<AttributeSchema> for LuaAttributeSchema {
    fn from(value: AttributeSchema) -> Self {
        LuaAttributeSchema {
            name: value.name.into_string(),
            attribute_type: value.attribute_type,
            is_list: value.is_list,
            is_visible: value.is_visible,
            is_editable: value.is_editable,
            is_hardcoded: value.is_hardcoded,
            is_readonly: value.is_hardcoded,
        }
    }
}

impl From<AttributeList> for LuaAttributeList {
    fn from(value: AttributeList) -> Self {
        LuaAttributeList {
            attributes: value
                .attributes
                .into_iter()
                .map(|a| (a.name.to_string(), a.into()))
                .collect(),
        }
    }
}

impl From<Schema> for LuaSchema {
    fn from(value: Schema) -> Self {
        LuaSchema {
            user_attributes: value.user_attributes.into(),
            group_attributes: value.group_attributes.into(),
            extra_user_object_classes: value
                .extra_user_object_classes
                .into_iter()
                .map(|a| (a.into_string(), true))
                .collect(),
            extra_group_object_classes: value
                .extra_group_object_classes
                .into_iter()
                .map(|a| (a.into_string(), true))
                .collect(),
        }
    }
}
