use serde::{Deserialize, Serialize};

use crate::types::{AttributeName, AttributeType, LdapObjectClass};

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct Schema {
    pub user_attributes: AttributeList,
    pub group_attributes: AttributeList,
    pub extra_user_object_classes: Vec<LdapObjectClass>,
    pub extra_group_object_classes: Vec<LdapObjectClass>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct AttributeSchema {
    pub name: AttributeName,
    //TODO: pub aliases: Vec<String>,
    pub attribute_type: AttributeType,
    pub is_list: bool,
    pub is_visible: bool,
    pub is_editable: bool,
    pub is_hardcoded: bool,
    pub is_readonly: bool,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct AttributeList {
    pub attributes: Vec<AttributeSchema>,
}

impl AttributeList {
    pub fn get_attribute_schema(&self, name: &AttributeName) -> Option<&AttributeSchema> {
        self.attributes.iter().find(|a| a.name == *name)
    }

    pub fn get_attribute_type(&self, name: &AttributeName) -> Option<(AttributeType, bool)> {
        self.get_attribute_schema(name)
            .map(|a| (a.attribute_type, a.is_list))
    }

    pub fn format_for_ldap_schema_description(&self) -> String {
        self.attributes
            .iter()
            .map(|a| a.name.as_str())
            // .unique()
            .collect::<Vec<_>>()
            .join(" $ ")
    }
}
