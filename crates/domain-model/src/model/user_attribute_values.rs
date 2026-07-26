use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

use lldap_domain::types::{AttributeName, Serialized, UserId};

// One row per value of a multi-value attribute, so that a filter can match a single value:
// `user_attributes` stores the whole list as one blob, which is only comparable as a unit.
// Derived from that blob, which stays the source of truth.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "user_attribute_values")]
pub struct Model {
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "user_attribute_value_user_id"
    )]
    pub user_id: UserId,
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "user_attribute_value_name"
    )]
    pub attribute_name: AttributeName,
    // Position in the list, to keep duplicate values distinct under the primary key.
    #[sea_orm(
        primary_key,
        auto_increment = false,
        column_name = "user_attribute_value_index"
    )]
    pub value_index: i32,
    #[sea_orm(column_name = "user_attribute_value")]
    pub value: Serialized,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::users::Entity",
        from = "Column::UserId",
        to = "super::users::Column::UserId",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Users,
    #[sea_orm(
        belongs_to = "super::user_attribute_schema::Entity",
        from = "Column::AttributeName",
        to = "super::user_attribute_schema::Column::AttributeName",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    UserAttributeSchema,
}

impl Related<super::User> for Entity {
    fn to() -> RelationDef {
        Relation::Users.def()
    }
}

impl Related<super::UserAttributeSchema> for Entity {
    fn to() -> RelationDef {
        Relation::UserAttributeSchema.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
