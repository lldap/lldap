use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use lldap_domain::schema::AttributeSchema;
use lldap_domain::types::{AttributeName, AttributeType};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "user_attribute_schema")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "user_attribute_schema_name"
    )]
    pub attribute_name: AttributeName,
    #[sea_orm(column_name = "user_attribute_schema_type")]
    pub attribute_type: AttributeType,
    #[sea_orm(column_name = "user_attribute_schema_is_list")]
    pub is_list: bool,
    #[sea_orm(column_name = "user_attribute_schema_is_user_visible")]
    pub is_user_visible: bool,
    #[sea_orm(column_name = "user_attribute_schema_is_user_editable")]
    pub is_user_editable: bool,
    #[sea_orm(column_name = "user_attribute_schema_is_hardcoded")]
    pub is_hardcoded: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::user_attributes::Entity")]
    UserAttributes,
}

impl Related<super::UserAttributes> for Entity {
    fn to() -> RelationDef {
        Relation::UserAttributes.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for AttributeSchema {
    fn from(value: Model) -> Self {
        Self {
            name: value.attribute_name,
            attribute_type: value.attribute_type,
            is_list: value.is_list,
            is_visible: value.is_user_visible,
            is_editable: value.is_user_editable,
            is_hardcoded: value.is_hardcoded,
            is_readonly: false,
        }
    }
}
