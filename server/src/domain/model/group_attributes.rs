use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use lldap_domain::types::{AttributeName, AttributeValue, GroupId, Serialized};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "group_attributes")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "group_attribute_group_id"
    )]
    pub group_id: GroupId,
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "group_attribute_name"
    )]
    pub attribute_name: AttributeName,
    #[sea_orm(column_name = "group_attribute_value")]
    pub value: Serialized,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::groups::Entity",
        from = "Column::GroupId",
        to = "super::groups::Column::GroupId",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Groups,
    #[sea_orm(
        belongs_to = "super::group_attribute_schema::Entity",
        from = "Column::AttributeName",
        to = "super::group_attribute_schema::Column::AttributeName",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    GroupAttributeSchema,
}

impl Related<super::Group> for Entity {
    fn to() -> RelationDef {
        Relation::Groups.def()
    }
}

impl Related<super::GroupAttributeSchema> for Entity {
    fn to() -> RelationDef {
        Relation::GroupAttributeSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Model> for AttributeValue {
    fn from(
        Model {
            group_id: _,
            attribute_name,
            value,
        }: Model,
    ) -> Self {
        Self {
            name: attribute_name,
            value,
        }
    }
}
